"""Model-assisted severity read — the one input the rules cannot supply.

Adjudication's other three inputs are mechanical: program policy is looked up,
demonstrated impact is classified from text, CVSS is arithmetic. None of them can
answer the question a program actually asks: *does this asset matter to this
business?*

An IDOR on a staging invoice viewer and an IDOR on the billing console are the
same technical finding and different payouts. That judgment needs the model.

Design constraints, all deliberate:

- **One call per finding, bounded output.** This runs once at the end of a scan
  over a handful of findings; it must not become a second agent.
- **The model proposes, the adjudicator disposes.** A model rating can raise a
  finding but cannot rescue one carrying a program disqualifier. The rule layer
  already enforces that, so this module just reports.
- **Failure is inert.** No key, no network, a bad response — the adjudication
  runs on its other three inputs and says the model term was unavailable.
  Severity must never depend on this call succeeding.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any

from baz.config import load_settings


logger = logging.getLogger(__name__)


RATINGS = ("none", "low", "medium", "high", "critical")

_PROMPT = """You are rating a security finding for a bug bounty submission.

Rate by what a program would actually pay for, not by CVSS alone. Consider:
- what asset this is and how much the business depends on it
- whether the data exposed is sensitive, regulated, or merely internal
- whether exploitation needs user interaction, an account, or nothing
- whether the program's own threat model would treat this as in scope

Finding:
  title: {title}
  target: {target}
  endpoint: {endpoint}
  claimed severity: {severity}
  impact: {impact}
  description: {description}
  demonstrated: {reproduction}
  policy note: {policy}

Reply with JSON only:
{{"rating": "none|low|medium|high|critical", "reasoning": "one sentence"}}"""


def _clip(value: Any, limit: int) -> str:
    text = " ".join(str(value or "").split())
    return text[:limit]


async def model_rating(
    report: dict[str, Any],
    *,
    model: str | None = None,
    policy_note: str = "",
    timeout: float = 45.0,
) -> tuple[str, str]:
    """Ask the model how it would rate this finding.

    Returns ``(rating, reasoning)``; ``("", "")`` when the call is unavailable.
    Never raises.
    """
    try:
        from litellm import acompletion  # noqa: PLC0415 - heavy import, only when used
    except ImportError:  # pragma: no cover - litellm is a hard dependency
        logger.debug("litellm unavailable; skipping model severity read")
        return "", ""

    resolved = model or _default_model()
    if not resolved:
        logger.debug("no model configured; skipping model severity read")
        return "", ""

    raw_repro = report.get("reproduction")
    reproduction = raw_repro if isinstance(raw_repro, dict) else {}
    prompt = _PROMPT.format(
        title=_clip(report.get("title"), 200),
        target=_clip(report.get("target"), 200),
        endpoint=_clip(report.get("endpoint"), 200),
        severity=_clip(report.get("severity"), 20),
        impact=_clip(report.get("impact"), 600),
        description=_clip(report.get("description"), 600),
        demonstrated=_clip(
            f"{reproduction.get('verdict', '')} {reproduction.get('stdout', '')}", 400
        ),
        policy=_clip(policy_note, 300),
    )

    try:
        response = await asyncio.wait_for(
            acompletion(
                model=resolved,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=200,
                temperature=0,
            ),
            timeout=timeout,
        )
    except Exception as exc:  # noqa: BLE001 - advisory call, must never break a scan
        logger.info("model severity read unavailable: %s", exc)
        return "", ""

    try:
        text = response.choices[0].message.content or ""
    except (AttributeError, IndexError, KeyError):
        return "", ""
    return _parse(text)


def _parse(text: str) -> tuple[str, str]:
    """Pull a rating out of whatever the model returned, or give up quietly."""
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            payload = json.loads(match.group(0))
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict):
            rating = str(payload.get("rating") or "").strip().lower()
            reasoning = str(payload.get("reasoning") or "").strip()
            if rating in RATINGS:
                return rating, reasoning[:300]

    lowered = text.strip().lower()
    for rating in RATINGS:
        if re.search(rf"\b{rating}\b", lowered):
            return rating, " ".join(text.split())[:300]
    return "", ""


def _default_model() -> str:
    try:
        return str(load_settings().llm.model or "")
    except (AttributeError, RuntimeError, ValueError):
        return ""


async def model_ratings_for(
    reports: list[dict[str, Any]],
    *,
    model: str | None = None,
    policy_notes: dict[str, str] | None = None,
    concurrency: int = 4,
) -> dict[str, tuple[str, str]]:
    """Rate several findings concurrently, bounded.

    Concurrency is capped because this runs at the end of an already-expensive
    scan; four at a time finishes a typical finding set in a couple of seconds
    without a burst against the provider.
    """
    if not reports:
        return {}

    policy_notes = policy_notes or {}
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def one(report: dict[str, Any]) -> tuple[str, tuple[str, str]]:
        report_id = str(report.get("id") or "")
        async with semaphore:
            rating, reasoning = await model_rating(
                report, model=model, policy_note=policy_notes.get(report_id, "")
            )
        return report_id, (rating, reasoning)

    results = await asyncio.gather(*(one(r) for r in reports), return_exceptions=True)
    out: dict[str, tuple[str, str]] = {}
    for item in results:
        if isinstance(item, BaseException):
            logger.debug("model severity read failed for one finding: %s", item)
            continue
        report_id, value = item
        if value[0]:
            out[report_id] = value
    return out
