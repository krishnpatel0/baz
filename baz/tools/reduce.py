"""Rewrite the reducer so it drops columns, never findings.

The first version capped output at 60 rows, which reintroduced the exact flaw it
was built to fix: an interesting anomaly at row 247 sat in the omitted set, and
the agent would never see it. That is the same failure mode as head/tail
truncation, just with a nicer-looking artifact.

The corrected principle: **reduce by column, not by row.**

- Every distinct finding is preserved. Nothing is omitted, so nothing
  interesting can hide in a dropped middle.
- Redundant *fields* are dropped — the 500th identical JSON object's `template`,
  `matcher-name`, `timestamp`, `curl-command`, `extracted-results` and so on.
- Rows that are byte-identical after column selection collapse into a count
  (`[x312]`), which is lossless aggregation rather than loss.
- Severity sorting is kept, so the top of the table is where the agent looks
  first.
- A handle to the raw text is always attached, so any row can be reopened.

A full 500-row table of `code | url` is roughly 4k tokens where the raw JSON was
42k. Same findings, 90% smaller, and no sampling decision anywhere.
"""

from __future__ import annotations

import json
import logging
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any


logger = logging.getLogger(__name__)


MAX_TABLE_TOKENS = 12_000
"""Ceiling on the rendered table, not on the findings it represents.

Set from the configured tool-output budget: reducing to something the output
bound would immediately truncate is pointless. When a table genuinely exceeds
this — a scan returning 50,000 findings — rows are folded by *group* rather than
by truncation: the table becomes per-severity and per-code counts, which still
accounts for every finding.
"""

_ROWS_TOKEN_ESTIMATE = 6
"""Approximate tokens per rendered row, for the budget check above."""


@dataclass(slots=True)
class Reduction:
    """A compact view of a tool's output that omits no finding."""

    tool: str
    table: str
    total: int
    """Distinct findings represented. Never fewer than the input had."""
    rows: int
    """Rendered rows, which is <= total once identical rows collapse."""
    note: str = ""
    omitted: int = 0
    """Findings not individually rendered. Zero unless the table hit its budget."""
    handle: str = ""
    """Path or id for the raw text, when the caller has one."""

    def to_text(self) -> str:
        header = f"{self.tool}: {self.total} finding(s)"
        if self.rows != self.total:
            header += f" in {self.rows} distinct row(s)"
        if self.omitted:
            header += f"; {self.omitted} folded into the groups shown"
        if self.note:
            header += f" — {self.note}"
        if self.handle:
            header += f"\nfull output: {self.handle}"
        return f"{header}\n\n{self.table}"


def _table(headers: list[str], rows: list[list[str]]) -> str:
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


def _clip(value: Any, limit: int = 90) -> str:
    text = " ".join(str(value if value is not None else "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _collapse(rows: list[list[str]]) -> tuple[list[list[str]], int]:
    """Fold byte-identical rows into a count, keeping one representative.

    Lossless: the count preserves how many findings are represented, and every
    distinct row still appears. Returns the folded rows and how many findings
    were merged away.
    """
    counts: Counter[tuple[str, ...]] = Counter(tuple(row) for row in rows)
    folded: list[list[str]] = []
    merged = 0
    for key, count in counts.items():
        row = list(key)
        if count > 1:
            row[-1] = f"{row[-1]} [x{count}]"
            merged += count - 1
        folded.append(row)
    return folded, merged


def _fit_budget(rows: list[list[str]], headers: list[str]) -> tuple[list[list[str]], int]:
    """Shrink a table that exceeds the budget by grouping, never by truncation.

    Returns the rows to render and how many findings those rows account for but
    do not individually list. Grouping keeps the totals honest: the agent sees
    "312 x 404" rather than 312 invisible findings.
    """
    if len(rows) * _ROWS_TOKEN_ESTIMATE <= MAX_TABLE_TOKENS:
        return rows, 0

    # Group by the first two columns (usually severity/code + a category) and
    # count. Every finding is still represented, as a group.
    grouped: Counter[tuple[str, str]] = Counter(
        (row[0], row[1] if len(row) > 1 else "") for row in rows
    )
    compact = [[key[0], key[1], f"x{count}"] for key, count in grouped.most_common()]
    accounted = sum(count for count in grouped.values())
    return compact, max(0, accounted - len(compact))


# --- per-tool reducers ------------------------------------------------------


def _nuclei(text: str) -> Reduction | None:
    """severity | template | host | matched-at | cve — one row per finding."""
    rows: list[list[str]] = []
    seen: set[tuple[str, ...]] = set()
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
        severity = str(info.get("severity", "")).lower()
        template = str(item.get("template-id") or item.get("template"))
        host = str(item.get("host") or "")
        matched = str(item.get("matched-at") or "")
        cve = item.get("cve-id") or (info.get("classification") or {}).get("cve-id")
        cve_text = ",".join(cve) if isinstance(cve, list) else str(cve or "")
        key = (severity, template, matched or host)
        if key in seen:
            continue
        seen.add(key)
        rows.append([severity, template, host, matched, cve_text])

    if not rows:
        return None
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    rows.sort(key=lambda r: (order.get(r[0], 5), r[1]))
    folded, merged = _collapse(rows)
    fitted, grouped = _fit_budget(folded, ["sev", "template", "host", "matched-at", "cve"])
    note = "sorted by severity"
    if merged:
        note += f"; {merged} duplicate row(s) collapsed"
    return Reduction(
        tool="nuclei",
        table=_table(["sev", "template", "host", "matched-at", "cve"], fitted),
        total=len(rows),
        rows=len(fitted),
        omitted=grouped,
        note=note,
    )


def _ffuf(text: str) -> Reduction | None:
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
            _clip(item.get("length"), 9),
            _clip(item.get("words"), 8),
            _clip(item.get("url"), 78),
        ]
        for item in results
        if isinstance(item, dict)
    ]
    if not rows:
        return None
    folded, merged = _collapse(rows)
    fitted, grouped = _fit_budget(folded, ["code", "size", "words", "url"])
    note = f"{merged} duplicate row(s) collapsed" if merged else ""
    return Reduction(
        tool="ffuf",
        table=_table(["code", "size", "words", "url"], fitted),
        total=len(rows),
        rows=len(fitted),
        omitted=grouped,
        note=note,
    )


def _httpx(text: str) -> Reduction | None:
    rows: list[list[str]] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped.startswith("{"):
            continue
        try:
            item = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        url = item.get("url")
        if not url or url in seen:
            continue
        seen.add(str(url))
        tech = item.get("tech") or item.get("technologies") or []
        rows.append(
            [
                _clip(item.get("status_code") or item.get("status-code"), 5),
                _clip(url, 60),
                _clip(item.get("title"), 30),
                _clip(",".join(tech) if isinstance(tech, list) else tech, 36),
            ]
        )
    if not rows:
        return None
    folded, merged = _collapse(rows)
    fitted, grouped = _fit_budget(folded, ["code", "url", "title", "tech"])
    note = f"{merged} duplicate row(s) collapsed" if merged else ""
    return Reduction(
        tool="httpx",
        table=_table(["code", "url", "title", "tech"], fitted),
        total=len(rows),
        rows=len(fitted),
        omitted=grouped,
        note=note,
    )


def _sqlmap(text: str) -> Reduction | None:
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
                rows.append([_clip(parameter, 24), _clip(kind, 28), _clip(title, 60)])
    if not rows:
        return None
    folded, merged = _collapse(rows)
    note = f"{merged} duplicate row(s) collapsed" if merged else ""
    return Reduction(
        tool="sqlmap",
        table=_table(["parameter", "type", "title"], folded),
        total=len(rows),
        rows=len(folded),
        note=note,
    )


def _dalfox(text: str) -> Reduction | None:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if isinstance(data, dict):
        items = data.get("findings")
    elif isinstance(data, list):
        items = data
    else:
        return None
    if not isinstance(items, list):
        return None
    rows = [
        [
            _clip(item.get("param"), 22),
            _clip(item.get("type"), 20),
            _clip(item.get("evidence") or item.get("message"), 70),
        ]
        for item in items
        if isinstance(item, dict)
    ]
    if not rows:
        return None
    folded, merged = _collapse(rows)
    note = f"{merged} duplicate row(s) collapsed" if merged else ""
    return Reduction(
        tool="dalfox",
        table=_table(["param", "type", "evidence"], folded),
        total=len(rows),
        rows=len(folded),
        note=note,
    )


_REDUCERS = (_nuclei, _ffuf, _httpx, _sqlmap, _dalfox)

_HINTS = {
    "nuclei": re.compile(r'"template-id"|"matched-at"'),
    "ffuf": re.compile(r'"results"\s*:\s*\['),
    "httpx": re.compile(r'"status_code"|"status-code"'),
    "sqlmap": re.compile(r"sqlmap identified|Parameter:"),
    "dalfox": re.compile(r'"findings"|\[POC\]'),
}


def reduce_output(text: str, *, hint: str = "") -> Reduction | None:
    """Reduce scanner output to a table that omits no finding, or None.

    ``hint`` reorders the reducers when the caller knows the tool; detection
    still validates the format, so a wrong hint cannot produce a wrong table.
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
