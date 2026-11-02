"""Budgeted context management — reduction, then eviction, then recording.

Three mechanisms, applied in order, each cheaper than the next:

1. **Reduction** (``baz.tools.reduce``) — when a tool result enters context,
   collapse it to a table that omits no finding. Cheapest, applied first,
   improves quality rather than risking it.

2. **Eviction** (this module) — as a run progresses, replace *aged* tool results
   with stand-ins. Only fires on results the agent has already reasoned about,
   never on recent ones, and every stand-in points at the full text.

3. **Recording** (``working_memory`` skill) — the discipline that makes eviction
   safe. What an agent concluded is written to notes/coverage while the evidence
   is fresh, so the transcript can let go of the bytes.

The order matters: reduction removes redundancy without losing anything, so it
should always run. Eviction trades detail for space, so it runs later and only
on what has been digested. Recording is what the agent does, not what the
harness does — but the harness makes the other two gentle enough that a
diligent agent loses nothing.

## Why eviction does not harm quality, concretely

An agent reads ffuf output, decides `/backup.sql` is worth pursuing, and notes
it. Twenty turns later that 40k-token dump is replaced by:

```
[exec_command output evicted after 18 turns — 41203 chars]
ffuf: 340 finding(s) in 12 distinct row(s)
code  url
200   /backup.sql
...
full output: /workspace/.output/9f2a.txt
```

Nothing decision-relevant is gone. The note carries the conclusion, the
stand-in carries the shape, and the path carries the rest if it is ever needed
again. The scan keeps 40k tokens of working room instead of paying to re-send a
result it already used.
"""

from __future__ import annotations

import logging
from typing import Any

from baz.core.eviction import EVICT_ABOVE_TOKENS, KEEP_RECENT, EvictionPlan, estimate, evict


logger = logging.getLogger(__name__)


# Fraction of a model's context window at which management starts. 0.55 widened
# 20% to 0.66: still well below the compaction threshold, but late enough that
# a session gets more room to work before anything is touched. Eviction is
# cheap and reversible (the data is on disk); compaction is expensive and
# lossy. Doing the cheap thing first means compaction runs less often.
MANAGE_AT_FRACTION = 0.66

# Below this, do nothing at all — a short session does not need managing, and
# rewriting its history for no reason risks losing something. 24 widened 20% to
# 29 trues the same principle.
MIN_ITEMS = 29


def should_manage(items: list[Any], *, context_tokens: int) -> bool:
    """Whether this session is large enough to be worth managing."""
    if len(items) < MIN_ITEMS:
        return False
    stats = estimate(items)
    return stats["total_tokens"] >= int(context_tokens * MANAGE_AT_FRACTION)


def manage(
    items: list[Any], *, context_tokens: int, keep_recent: int = KEEP_RECENT
) -> tuple[list[Any], EvictionPlan]:
    """Apply eviction when the session warrants it, otherwise return unchanged.

    Returns the (possibly rewritten) items and a plan. A no-op plan means the
    session was small enough that managing it would have cost more than it
    saved — the common case early in a run.
    """
    if not should_manage(items, context_tokens=context_tokens):
        return items, EvictionPlan()

    before = estimate(items)
    rewritten, plan = evict(items, keep_recent=keep_recent)
    if not plan.evicted:
        return items, plan

    after = estimate(rewritten)
    logger.info(
        "context managed: %s total items %d->%d, tool tokens %d->%d",
        plan.summary(),
        before["items"],
        after["items"],
        before["tool_tokens"],
        after["tool_tokens"],
    )
    return rewritten, plan


__all__ = [
    "EVICT_ABOVE_TOKENS",
    "KEEP_RECENT",
    "MANAGE_AT_FRACTION",
    "EvictionPlan",
    "estimate",
    "evict",
    "manage",
    "should_manage",
]
