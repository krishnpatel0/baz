"""Late evidence collection for findings filed before the pipeline was wired.

Filing a report now gathers its proof by default. Reports filed by an older
build — or by a scan that was interrupted before the gathering step ran — carry
no bundle, so their ``.md`` renders with no screenshots even though the sandbox
still holds the pixels.

This module closes that gap at finalize time: for every finding whose bundle is
missing or empty it opens the folder, gathers what the sandbox still has, seals
the finding, and points the report at the bundle. It is deliberately
best-effort — a scan that ends must never fail because a screenshot aged out —
and it reports how many findings it enriched so the caller can log it.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


async def backfill_run_evidence(
    *,
    run_dir: Path,
    reports: list[dict[str, Any]],
    sandbox_session: Any,
) -> int:
    """Attach the sandbox's remaining evidence to findings that have none.

    Returns the number of findings that gained at least one artifact. Findings
    that already have a sealed bundle are left untouched: re-sealing would
    discard the artifact list the report was rendered from.
    """
    if sandbox_session is None or not reports:
        return 0

    from baz.evidence import open_bundle
    from baz.evidence.gather import capture_http_exchange, collect_screenshots

    enriched = 0
    for report in reports:
        report_id = report.get("id")
        title = report.get("title")
        if not isinstance(report_id, str) or not report_id:
            continue
        if not isinstance(title, str) or not title:
            title = report_id

        bundle_path = report.get("evidence_bundle")
        if _has_sealed_bundle(bundle_path):
            continue

        try:
            bundle = open_bundle(run_dir, report_id, title)
        except (OSError, ValueError):
            logger.exception("could not open bundle for backfill: %s", report_id)
            continue

        before = len(bundle.captures)
        try:
            await collect_screenshots(bundle, sandbox_session)
            for exchange_id in _exchange_ids(report):
                try:
                    await capture_http_exchange(bundle, exchange_id)
                except Exception:
                    logger.debug("backfill: exchange %s unavailable", exchange_id, exc_info=True)
        except Exception:
            logger.exception("backfill gathering failed for %s", report_id)

        if len(bundle.captures) <= before:
            continue

        try:
            bundle.seal(
                {
                    "id": report_id,
                    "title": title,
                    "severity": report.get("severity"),
                    "cvss": report.get("cvss"),
                    "target": report.get("target"),
                    "backfilled": True,
                }
            )
        except (OSError, ValueError):
            logger.exception("could not seal backfilled bundle for %s", report_id)
            continue

        report["evidence_bundle"] = str(bundle.root)
        _point_state_at_bundle(report_id, bundle.root)
        enriched += 1
        logger.info("Backfilled evidence for %s", report_id)

    return enriched


def _has_sealed_bundle(bundle_path: Any) -> bool:
    """True when the finding already has a sealed bundle of its own."""
    if not isinstance(bundle_path, str) or not bundle_path:
        return False
    return (Path(bundle_path) / "finding.json").is_file()


def _exchange_ids(report: dict[str, Any]) -> list[str]:
    raw = report.get("http_exchange_ids")
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, str) and item.strip()]


def _point_state_at_bundle(report_id: str, bundle_root: Path) -> None:
    """Record the new bundle on the live report state, so the report finds it."""
    try:
        from baz.report.state import get_global_report_state

        state = get_global_report_state()
        if state is not None:
            state.attach_evidence_bundle(report_id, str(bundle_root))
    except Exception:
        logger.debug("could not record backfilled bundle for %s", report_id, exc_info=True)
