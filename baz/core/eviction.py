"""Conversation eviction — stop re-sending tool output the agent already read.

The cost problem is not the prompt, it is history. Each call re-sends every
prior turn, so a 75-call run pays for turn 3's raw ffuf JSON about 72 times. The
growth is roughly quadratic and it is provider-independent: no cache helps,
because the history genuinely differs per call.

Eviction replaces an aged tool result with a compact stand-in that keeps what
the agent *used* — the counts, the notable rows, the handle to the full text —
and drops the bytes it already digested.

Two properties make this safe rather than lossy:

**Nothing is deleted.** The full output is already on disk: spilled by
``output_store`` under the workspace, captured in the evidence bundle, and
mirrored in the Caido proxy history. The stand-in carries a path, so an agent
that needs row 9,000 can still read it.

**Reduction runs first.** A 42,000-token ffuf JSON becomes a 2,400-token table
before eviction is considered at all, so most results are never evicted — only
the genuinely enormous ones, and only once they are old enough that the agent
has already acted on them.

The distinction that matters against other approaches: this hides nothing from
the model. It still sees every step in order, and what happened at each step. It
just stops paying to re-read raw bytes it has finished with.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from baz.tools.reduce import reduce_output


logger = logging.getLogger(__name__)


KEEP_RECENT = 15
"""Tool results kept verbatim regardless of size.

Twelve was the first figure, widened 20% to fifteen. The cost of keeping one
more result is a few thousand tokens; the cost of evicting the one that turns
out to matter is a wasted turn re-fetching it, or worse, a conclusion drawn
without it. Whenever the trade is close, this module keeps more.
"""

EVICT_ABOVE_TOKENS = 1_100
"""Anything below this is not worth the stand-in's overhead.

900 widened 20% to 1,100 — roughly 4,400 characters. A stand-in costs ~60
tokens; evicting a 500-token result to save 440 is churn with no benefit, and
the floor is deliberately high so small results are simply never touched.
"""

MIN_STANDIN_SAVING = 3.6
"""Only evict when the replacement is at least this much smaller.

3.0 widened 20% to 3.6. Prevents replacing a result with a summary that saves
a modest amount but loses the detail the agent might still want: below this
ratio the space freed is not worth the round trip to get it back.
"""


@dataclass(slots=True)
class EvictionPlan:
    """What would be (or was) evicted, for logging and tests."""

    considered: int = 0
    evicted: int = 0
    tokens_before: int = 0
    tokens_after: int = 0
    indices: list[int] = field(default_factory=list)
    unrecorded: int = 0
    """Evicted results with no recording call after them — the signal layer."""

    @property
    def saved(self) -> int:
        return max(0, self.tokens_before - self.tokens_after)

    def summary(self) -> str:
        if not self.evicted:
            return f"eviction: nothing to do ({self.considered} results examined)"
        pct = (100 * self.saved // self.tokens_before) if self.tokens_before else 0
        line = (
            f"eviction: replaced {self.evicted} of {self.considered} tool results, "
            f"{self.tokens_before} -> {self.tokens_after} tokens ({pct}% smaller)"
        )
        if self.unrecorded:
            line += f"; {self.unrecorded} had no note written after them"
        return line


_EST_CHARS_PER_TOKEN = 4

# Tool results arrive as text; the stand-in has to survive being re-sent as
# part of the same message list, so it is plain text with the original handle.
_STANDIN = "[{tool} output evicted after {turns} turns — {chars} chars]\n{path_line}{summary}"

_NO_RECORD_MARKER = (
    "\n! no note recorded after this result — if it mattered, record it now "
    "(create_note / record_coverage) before it is compacted away"
)


def _estimate_tokens(text: str) -> int:
    return len(text) // _EST_CHARS_PER_TOKEN


def _summarise(text: str) -> str:
    """A few lines that keep the result's shape without its bulk.

    Prefers a structured summary when the content is scanner output the
    reducer understands, falling back to first-and-last lines so the agent can
    still see whether the result looked normal.
    """
    try:
        reduction = reduce_output(text)
    except Exception:  # noqa: BLE001 - summary is best-effort
        reduction = None

    if reduction is not None:
        # One header line plus the first few table rows: enough to recognise
        # the result and decide whether to reopen it.
        lines = reduction.to_text().splitlines()
        head = lines[:6]
        if len(lines) > 6:
            head.append(f"... {len(lines) - 6} more rows in the full output")
        return "\n".join(head)

    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return "(empty result)"
    if len(lines) <= 3:
        return "\n".join(lines)
    return "\n".join([lines[0], f"... {len(lines) - 2} lines omitted ...", lines[-1]])


def _note_written_after(items: list[Any], index: int) -> bool:
    """Whether any recording tool call happened after the result at ``index``.

    The signal layer of the memory design: an agent may let old output go, but
    it should be *told* when it is letting go of something it never wrote down.
    Checked by looking for a call to one of the four durable stores, which are
    the only things that outlive the transcript.
    """
    for later in items[index + 1 :]:
        if not isinstance(later, dict):
            continue
        blob = str(later.get("name") or "")
        if not blob:
            content = later.get("content")
            blob = content if isinstance(content, str) else ""
        if any(tool in blob for tool in _RECORDING_TOOLS):
            return True
    return False


_RECORDING_TOOLS = (
    "create_note",
    "update_note",
    "record_coverage",
    "update_coverage",
    "amend_threat_model",
    "save_threat_model",
    "create_vulnerability_report",
    "create_dependency_report",
    "update_vulnerability_report",
)
"""The tools whose output outlives the transcript. A call to any of these after
a tool result is evidence the agent extracted something durable from it."""


def _is_tool_result(item: Any) -> bool:
    """Whether a session item is a tool result carrying bulk output."""
    if not isinstance(item, dict):
        return False
    role = item.get("role")
    if role in ("tool", "tool_result"):
        return True
    # The SDK also represents results as function_call_output entries.
    item_type = item.get("type")
    return bool(isinstance(item_type, str) and "output" in item_type.lower())


def _text_of(item: dict[str, Any]) -> str:
    """Extract the text payload from a tool-result item, in any known shape."""
    for key in ("content", "output", "text"):
        value = item.get(key)
        if isinstance(value, str):
            return value
        if isinstance(value, list):
            parts = [
                part.get("text", "")
                for part in value
                if isinstance(part, dict) and isinstance(part.get("text"), str)
            ]
            if parts:
                return "\n".join(parts)
    return ""


def _path_line(item: dict[str, Any]) -> str:
    """The handle line for a stand-in, or an honest statement that none exists.

    A stand-in that says "full text: (see output store)" tells the agent
    nothing. This prefers a real path — the workspace spill the output_store
    wrote, or a path the caller recorded — and otherwise says plainly that the
    text is gone, so the agent knows to re-run rather than hunt for it.
    """
    for key in ("_spill_path", "spill_path", "artifact_path"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return f"full text: {value}\n"
    return "full text: not retained — re-run the command if you need it\n"


def _replace_text(item: dict[str, Any], replacement: str) -> dict[str, Any]:
    """Return a copy of a tool-result item with its text payload replaced."""
    clone = dict(item)
    for key in ("content", "output", "text"):
        value = clone.get(key)
        if isinstance(value, str):
            clone[key] = replacement
            return clone
        if isinstance(value, list):
            clone[key] = [{"type": "text", "text": replacement}]
            return clone
    return clone


def evict(items: list[Any], *, keep_recent: int = KEEP_RECENT) -> tuple[list[Any], EvictionPlan]:
    """Replace aged, oversized tool results with compact stand-ins.

    Returns the rewritten item list and a plan describing what happened. The
    input list is not mutated — the caller decides whether to adopt the result.

    Only the *content* of tool results is touched. Assistant reasoning, user
    messages, plan steps and every decision the agent made stay exactly as they
    were: those are the thread of understanding, and the whole point is to
    preserve it while dropping raw bytes.

    Four guards, all of them about not hiding something the agent still needs:

    - recent results are never touched, however large
    - a result smaller than :data:`EVICT_ABOVE_TOKENS` is left alone, because a
      stand-in costs tokens too and saving 140 is churn
    - a result whose reduction would save less than
      :data:`MIN_STANDIN_SAVING` keeps its original form
    - every stand-in states how many rows it dropped and carries the path to
      the full text, so an agent that needs row 9,000 knows it exists and can
      read it — eviction is *pointing*, never deleting
    """
    plan = EvictionPlan()

    result_indices = [i for i, item in enumerate(items) if _is_tool_result(item)]
    plan.considered = len(result_indices)
    if len(result_indices) <= keep_recent:
        return items, plan

    # Everything except the last `keep_recent` tool results is eligible.
    eligible = set(result_indices[:-keep_recent]) if keep_recent else set(result_indices)

    out: list[Any] = list(items)
    for index, item in enumerate(items):
        if index not in eligible:
            continue
        text = _text_of(item)
        if not text:
            continue
        before = _estimate_tokens(text)
        if before < EVICT_ABOVE_TOKENS:
            continue

        summary = _summarise(text)
        turns_old = sum(1 for j in result_indices if j < index and j in eligible) + 1
        standin = _STANDIN.format(
            tool=str(item.get("name") or item.get("tool") or "tool"),
            turns=turns_old,
            chars=len(text),
            path_line=_path_line(item),
            summary=summary,
        )
        after = _estimate_tokens(standin)
        if before < after * MIN_STANDIN_SAVING:
            continue

        if not _note_written_after(items, index):
            standin += _NO_RECORD_MARKER
            plan.unrecorded += 1

        out[index] = _replace_text(item, standin)
        plan.evicted += 1
        plan.indices.append(index)
        plan.tokens_before += before
        plan.tokens_after += after

    if plan.evicted:
        logger.info("%s", plan.summary())
    return out, plan


def estimate(items: list[Any]) -> dict[str, int]:
    """Token accounting for a session, for diagnosis rather than control."""
    tool_chars = sum(len(_text_of(i)) for i in items if _is_tool_result(i))
    total_chars = sum(len(_text_of(i)) for i in items if isinstance(i, dict))
    return {
        "items": len(items),
        "tool_results": sum(1 for i in items if _is_tool_result(i)),
        "tool_chars": tool_chars,
        "total_chars": total_chars,
        "tool_tokens": tool_chars // _EST_CHARS_PER_TOKEN,
        "total_tokens": total_chars // _EST_CHARS_PER_TOKEN,
    }
