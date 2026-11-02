"""End-of-scan verification — does it still reproduce on a clean slate?

Filing-time reproduction proves a finding was true *then*, in the session that
found it: warm caches, cookies the agent set, a container that had already
crawled the app. That is the state an attacker never has.

So before the report is written, every replay-safe finding is re-run from a
fresh container. Three outcomes, and the middle one matters most:

- reproduces again          -> verified, evidence is trustworthy
- reproduces some of the time -> flaky, and the *rate* is the finding's real
                                 character; a race condition that only fires
                                 once in five is not the same claim as one that
                                 fires every time
- does not reproduce        -> downgraded to needs_review, never silently kept

The last one is the point. A finding that only existed in the agent's own
session state is not a bug report, it is a testing artifact.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from baz.evidence.repro import ReproRequest, run_repro


logger = logging.getLogger(__name__)


FRESH_CONTAINER_REASON = "re-run in a fresh sandbox to prove it survives session state"


class Outcome:
    VERIFIED = "verified"
    FLAKY = "flaky"
    NOT_REPRODUCED = "not_reproduced"
    SKIPPED = "skipped"


@dataclass(slots=True)
class FindingVerification:
    report_id: str
    title: str
    outcome: str
    attempts: int
    successes: int
    reason: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.outcome in (Outcome.VERIFIED, Outcome.FLAKY)

    def summary(self) -> str:
        if self.outcome == Outcome.SKIPPED:
            return f"{self.title}: skipped ({self.reason})"
        return f"{self.title}: {self.outcome} {self.successes}/{self.attempts} ({self.reason})"

    def to_wire(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "title": self.title,
            "outcome": self.outcome,
            "attempts": self.attempts,
            "successes": self.successes,
            "reason": self.reason,
            **self.detail,
        }


def _repro_of(report: dict[str, Any]) -> tuple[str, bool] | None:
    """Return ``(script, replay_safe)`` for a finding, or None if unverifiable."""
    record = report.get("reproduction")
    if not isinstance(record, dict):
        return None
    script = record.get("script") or report.get("poc_script_code") or ""
    if not isinstance(script, str) or not script.strip():
        return None
    return script, bool(record.get("replay_safe", True))


async def verify_findings(
    reports: list[dict[str, Any]],
    fresh_session_factory: Any,
    *,
    attempts: int = 2,
) -> list[FindingVerification]:
    """Re-run every replay-safe finding's repro in a fresh sandbox.

    ``fresh_session_factory`` is an async callable returning a started sandbox
    session; it is called once and reused so the verification is not paying
    container-startup cost per finding. The caller owns teardown.

    ``attempts > 1`` exists to separate a real finding from a racy one: a single
    re-run cannot tell "always" from "once in three", and that difference is the
    finding's character.
    """
    results: list[FindingVerification] = []

    candidates: list[tuple[dict[str, Any], str]] = []
    for report in reports:
        report_id = str(report.get("id") or "?")
        title = str(report.get("title") or "untitled")
        parsed = _repro_of(report)
        if parsed is None:
            results.append(
                FindingVerification(
                    report_id, title, Outcome.SKIPPED, 0, 0, "no reproduction recorded"
                )
            )
            continue
        script, replay_safe = parsed
        if not replay_safe:
            results.append(
                FindingVerification(
                    report_id,
                    title,
                    Outcome.SKIPPED,
                    0,
                    0,
                    "exploit is destructive to replay; verified once at filing",
                )
            )
            continue
        candidates.append((report, script))

    if not candidates:
        return results

    session = None
    try:
        session = await fresh_session_factory()
    except Exception as exc:
        logger.exception("could not start a fresh sandbox for verification")
        for report, _script in candidates:
            results.append(
                FindingVerification(
                    str(report.get("id") or "?"),
                    str(report.get("title") or "untitled"),
                    Outcome.SKIPPED,
                    0,
                    0,
                    f"fresh sandbox unavailable: {exc}",
                )
            )
        return results

    for report, script in candidates:
        report_id = str(report.get("id") or "?")
        title = str(report.get("title") or "untitled")
        successes = 0
        last = None
        for _ in range(max(1, attempts)):
            last = await run_repro(session, ReproRequest(script=script, replay_safe=True))
            if last.ok:
                successes += 1

        if successes == attempts:
            outcome, reason = Outcome.VERIFIED, "reproduced every attempt in a fresh sandbox"
        elif successes > 0:
            outcome, reason = Outcome.FLAKY, f"reproduced {successes}/{attempts} attempts"
        else:
            outcome, reason = (
                Outcome.NOT_REPRODUCED,
                "did not reproduce in a fresh sandbox — likely depended on session state",
            )

        results.append(
            FindingVerification(
                report_id,
                title,
                outcome,
                attempts,
                successes,
                reason,
                detail={"last_run": last.to_wire() if last is not None else {}},
            )
        )
    return results


def apply_outcomes(
    reports: list[dict[str, Any]],
    verifications: list[FindingVerification],
) -> dict[str, int]:
    """Stamp verification outcomes onto the findings and count the verdicts.

    A finding that failed to reproduce is downgraded to ``needs_review`` — not
    deleted. It stays visible with its status attached, because "we could not
    re-prove this" is information the hunter needs; silently dropping it would
    hide both the finding and the doubt about it.
    """
    by_id = {v.report_id: v for v in verifications}
    outcomes = (Outcome.VERIFIED, Outcome.FLAKY, Outcome.NOT_REPRODUCED, Outcome.SKIPPED)
    counts = dict.fromkeys(outcomes, 0)

    for report in reports:
        report_id = str(report.get("id") or "?")
        verification = by_id.get(report_id)
        if verification is None:
            continue
        report["verification"] = verification.to_wire()
        counts[verification.outcome] = counts.get(verification.outcome, 0) + 1
        if verification.outcome == Outcome.NOT_REPRODUCED:
            report["verification_downgraded"] = True
    return counts
