"""Tool-output reduction — a table instead of a truncated blob.

The problem this solves is not size, it is *shape*. Today a 12,000-line
`nuclei` run arrives as 2,000 lines of head plus 2,000 of tail, and the
interesting result — an unusual severity, a single odd endpoint — is in the
dropped middle. The agent then reasons about a sample and reports "exhaustive".

Structured scanners already emit machine-readable output. Parsing it into a
compact table keeps every finding's *identity* while dropping its bulk: 400 rows
of `critical | CVE-2024-1234 | /admin` is ~4k tokens and loses nothing that
matters, where 400 raw JSON objects is ~40k and gets truncated anyway.

This is the A3 perception layer, applied at the point the output enters context.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any


logger = logging.getLogger(__name__)


MAX_ROWS = 60
"""Rows shown before summarising the rest. Enough to see the shape of a result
set, few enough to leave room for the agent to act on it."""


@dataclass(slots=True)
class Reduction:
    """A compact view of a tool's output, plus what was omitted."""

    tool: str
    table: str
    total: int
    shown: int
    note: str = ""
    shape: str = "rows"
    """``rows`` for a table of items, ``scalar`` for a summary value."""

    def to_text(self) -> str:
        header = f"{self.tool}: {self.total} result(s), showing {self.shown}"
        if self.note:
            header += f" — {self.note}"
        return f"{header}\n\n{self.table}"


def _table(headers: list[str], rows: list[list[str]]) -> str:
    """Fixed-width table; agents read alignment, and it costs no more tokens."""
    if not rows:
        return ""
    widths = [len(h) for h in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))
    lines = [
        "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)),
        "  ".join("-" * w for w in widths),
    ]
    lines.extend("  ".join(c.ljust(widths[i]) for i, c in enumerate(row)) for row in rows)
    return "\n".join(lines)


def _clip(value: Any, limit: int = 60) -> str:
    text = " ".join(str(value if value is not None else "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


# --- per-tool reducers ------------------------------------------------------
# Each returns None when the output is not in that tool's format, so detection
# can fall through rather than mis-parsing.


def _nuclei(text: str) -> Reduction | None:
    """nuclei JSONL: severity | template | host | matched-at | cve."""
    rows: list[list[str]] = []
    seen: set[tuple[str, str, str]] = set()
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped.startswith("{"):
            continue
        try:
            item = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if "template-id" not in item and "template" not in item:
            continue
        info = item.get("info") or {}
        key = (
            str(info.get("severity", "")),
            str(item.get("template-id") or item.get("template")),
            str(item.get("matched-at") or item.get("host")),
        )
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            [
                _clip(key[0], 9),
                _clip(key[1], 34),
                _clip(item.get("host"), 30),
                _clip(item.get("matched-at"), 40),
                _clip(item.get("cve-id") or info.get("classification", {}).get("cve-id"), 18),
            ]
        )
    if not rows:
        return None
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    rows.sort(key=lambda r: order.get(r[0], 5))
    shown = rows[:MAX_ROWS]
    return Reduction(
        tool="nuclei",
        table=_table(["sev", "template", "host", "matched-at", "cve"], shown),
        total=len(rows),
        shown=len(shown),
        note="sorted by severity"
        + (f"; {len(rows) - len(shown)} more omitted" if len(rows) > len(shown) else ""),
    )


def _ffuf(text: str) -> Reduction | None:
    """ffuf JSON: status | size | words | url."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        return None
    rows = [
        [
            _clip(item.get("status"), 6),
            _clip(item.get("length"), 8),
            _clip(item.get("words"), 7),
            _clip(item.get("url"), 72),
        ]
        for item in results
        if isinstance(item, dict)
    ]
    if not rows:
        return None
    shown = rows[:MAX_ROWS]
    return Reduction(
        tool="ffuf",
        table=_table(["code", "size", "words", "url"], shown),
        total=len(rows),
        shown=len(shown),
        note=f"{len(rows) - len(shown)} more omitted" if len(rows) > len(shown) else "",
    )


def _httpx(text: str) -> Reduction | None:
    """httpx JSONL: url | code | title | tech."""
    rows: list[list[str]] = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped.startswith("{"):
            continue
        try:
            item = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if "url" not in item:
            continue
        tech = item.get("tech") or item.get("technologies") or []
        rows.append(
            [
                _clip(item.get("status_code") or item.get("status-code"), 5),
                _clip(item.get("url"), 58),
                _clip(item.get("title"), 28),
                _clip(",".join(tech) if isinstance(tech, list) else tech, 34),
            ]
        )
    if not rows:
        return None
    shown = rows[:MAX_ROWS]
    return Reduction(
        tool="httpx",
        table=_table(["code", "url", "title", "tech"], shown),
        total=len(rows),
        shown=len(shown),
        note=f"{len(rows) - len(shown)} more omitted" if len(rows) > len(shown) else "",
    )


def _sqlmap(text: str) -> Reduction | None:
    """sqlmap text: parameter | type | title | payload presence."""
    if "sqlmap" not in text.lower() and "Parameter:" not in text:
        return None
    rows: list[list[str]] = []
    parameter = kind = title = ""
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("Parameter:"):
            parameter = line.split(":", 1)[1].strip()
        elif line.startswith("Type:"):
            kind = line.split(":", 1)[1].strip()
        elif line.startswith("Title:"):
            title = line.split(":", 1)[1].strip()
            if parameter:
                rows.append([_clip(parameter, 22), _clip(kind, 26), _clip(title, 50), "yes"])
    if not rows:
        return None
    return Reduction(
        tool="sqlmap",
        table=_table(["parameter", "type", "title", "injectable"], rows[:MAX_ROWS]),
        total=len(rows),
        shown=min(len(rows), MAX_ROWS),
    )


def _dalfox(text: str) -> Reduction | None:
    """dalfox JSON: param | type | evidence."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if isinstance(data, dict):
        items = data.get("findings")
    elif isinstance(data, list):
        items = data
    else:
        items = None
    if not isinstance(items, list):
        return None
    rows = [
        [
            _clip(item.get("param"), 20),
            _clip(item.get("type"), 18),
            _clip(item.get("evidence") or item.get("message"), 56),
        ]
        for item in items
        if isinstance(item, dict)
    ]
    if not rows:
        return None
    return Reduction(
        tool="dalfox",
        table=_table(["param", "type", "evidence"], rows[:MAX_ROWS]),
        total=len(rows),
        shown=min(len(rows), MAX_ROWS),
    )


_REDUCERS = (_nuclei, _ffuf, _httpx, _sqlmap, _dalfox)

# Cheap pre-filter: only attempt a parse when the text plausibly is that tool's
# output, so a 2 MB source file is not fed through five JSON parsers.
_HINTS = {
    "nuclei": re.compile(r'"template-id"|"matched-at"'),
    "ffuf": re.compile(r'"results"\s*:\s*\['),
    "httpx": re.compile(r'"status_code"|"status-code"'),
    "sqlmap": re.compile(r"sqlmap identified|Parameter:"),
    "dalfox": re.compile(r'"findings"|\[POC\]'),
}


def reduce_output(text: str, *, hint: str = "") -> Reduction | None:
    """Reduce a tool's output to a compact table, or None when not recognised.

    ``hint`` is the tool name when the caller knows it (parsed from the command
    line). It only reorders the reducers — detection still validates the format,
    because a gu-essed tool name with real output of another shape should not
    produce a wrong table.
    """
    if not text or len(text) < 200:
        return None

    candidates = list(_REDUCERS)
    if hint:
        key = hint.lower()
        candidates.sort(key=lambda fn: 0 if key in fn.__name__ else 1)

    for reducer in candidates:
        name = reducer.__name__.lstrip("_")
        pattern = _HINTS.get(name)
        if pattern and not pattern.search(text[:8000]):
            continue
        try:
            result = reducer(text)
        except (ValueError, TypeError, KeyError):
            logger.debug("reducer %s failed", name, exc_info=True)
            continue
        if result is not None:
            return result
    return None


def tool_from_command(command: str) -> str:
    """Best-effort tool name from a shell command line."""
    for name in ("nuclei", "ffuf", "httpx", "sqlmap", "dalfox", "katana", "dirsearch"):
        if re.search(rf"\b{name}\b", command):
            return name
    return ""
