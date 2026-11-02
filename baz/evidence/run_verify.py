"""Scan-level verification pass: re-prove every finding from a clean sandbox.

Runs in the runner's teardown, before the container is destroyed and before the
report is finalized. Split out of `runner.py` so the orchestration there stays
readable and so this can be tested without standing up a whole scan.
"""

from __future__ import annotations

import logging
from typing import Any

from baz.evidence.export import export_run
from baz.evidence.verify import FindingVerification, apply_outcomes, verify_findings
from baz.runtime import session_manager


logger = logging.getLogger(__name__)


async def run_verification_pass(
    *,
    scan_id: str,
    image: str,
    report_state: Any,
    status_sink: Any = None,
    attempts: int = 2,
) -> list[FindingVerification]:
    """Re-run every replay-safe finding in a fresh container.

    Returns the per-finding outcomes (also stamped onto the findings). An empty
    list means there was nothing to verify — not that everything passed.

    Best-effort by design: a verification failure must never prevent a report
    from being written. A finding that could not be re-run is reported as
    ``skipped`` with the reason, which is honest, rather than dropped.
    """
    if report_state is None:
        return []
    reports = report_state.get_existing_vulnerabilities()
    if not reports:
        return []

    verifiable = [r for r in reports if isinstance(r.get("reproduction"), dict)]
    if not verifiable:
        logger.info("verification pass: no findings carry a reproduction")
        return []

    async def fresh() -> Any:
        """A second, independent sandbox — no cookies, no cache, no prior state."""
        bundle = await session_manager.create_or_reuse(
            f"{scan_id}-verify",
            image=image,
            local_sources=[],
            extra_files=None,
            status_sink=status_sink,
            defer=False,
        )
        return bundle["session"]

    try:
        results = await verify_findings(reports, fresh, attempts=attempts)
    except (OSError, RuntimeError, ValueError):
        logger.exception("verification pass failed; findings keep their filing-time verdict")
        return []
    finally:
        try:
            await session_manager.cleanup(f"{scan_id}-verify")
        except (OSError, RuntimeError):
            # Teardown of the throwaway verifier container; Docker's own reaping
            # catches a stranded one, so this must not surface as a scan failure.
            logger.debug("verification sandbox cleanup failed", exc_info=True)

    counts = apply_outcomes(reports, results)
    for verification in results:
        logger.info("verification: %s", verification.summary())
    logger.info(
        "verification pass complete: %d verified, %d flaky, %d not reproduced, %d skipped",
        counts.get("verified", 0),
        counts.get("flaky", 0),
        counts.get("not_reproduced", 0),
        counts.get("skipped", 0),
    )
    return results


def write_submission_export(reports: Any, run_dir: Any) -> dict[str, Any]:
    """Write the platform-shaped submission export for a finished run.

    Best-effort: an export failure must not cost the run its report. Returns an
    empty manifest when there was nothing to export.
    """
    try:
        return export_run(list(reports or []), run_dir)
    except (OSError, ValueError):
        logger.exception("submission export failed; report is unaffected")
        return {}
