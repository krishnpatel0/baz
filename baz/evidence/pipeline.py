"""File-time evidence: store what the agent supplied, gather the rest, seal.

Called once per finding, from the reporting tool, at the moment the report is
filed. Everything the report will ever cite passes through here:

1. the payloads and the impact sample the agent supplied as arguments;
2. the screenshots, proxied exchanges and named files still inside the sandbox;
3. the seal — one immutable record of what the finding is and what proves it.

Isolating it from the tool keeps the filing path about validation and
deduplication, and makes the evidence rules testable without a scan. Nothing in
here may raise into the caller: the finding is already persisted, and an
artifact that could not be written is a packaging gap, not a reason to lose the
finding.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from baz.evidence.gather import copy_evidence_files, gather_default_evidence


if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


async def attach_finding_evidence(
    bundle: Any,
    *,
    bundle_dir: Path,
    report_state: Any,
    report_id: str,
    title: str,
    severity: str,
    cvss_score: float,
    target: str,
    endpoint: str | None,
    method: str | None,
    cwe: str | None,
    cve: str | None,
    impact: str,
    http_exchange_ids: list[str] | None,
    evidence_files: list[str] | None,
    sandbox_session: Any,
    payloads: list[dict[str, Any]] | None = None,
    impact_samples: list[Any] | None = None,
    impact_total_seen: int | None = None,
) -> tuple[list[str], list[str]]:
    """Record, gather and seal one finding's evidence.

    Returns ``(artifact_paths, warnings)``. The artifact list is read back off
    the sealed bundle, so the report can cite exactly what landed on disk rather
    than what the agent meant to supply.
    """
    warnings = _store_artifacts(
        bundle,
        payloads=payloads,
        impact_samples=impact_samples,
        impact_total_seen=impact_total_seen,
    )
    warnings.extend(
        await gather_default_evidence(
            bundle,
            sandbox_session=sandbox_session,
            http_exchange_ids=http_exchange_ids,
        )
    )
    warnings.extend(
        await copy_evidence_files(
            bundle,
            sandbox_session=sandbox_session,
            paths=evidence_files,
        )
    )
    _seal(
        bundle,
        report_id=report_id,
        title=title,
        severity=severity,
        cvss_score=cvss_score,
        target=target,
        endpoint=endpoint,
        method=method,
        cwe=cwe,
        cve=cve,
        impact=impact,
        http_exchange_ids=http_exchange_ids,
        evidence_files=evidence_files,
    )
    _record_on_report(report_state, report_id, bundle_dir)
    return [capture.path for capture in bundle.captures], warnings


def _store_artifacts(
    bundle: Any,
    *,
    payloads: list[dict[str, Any]] | None,
    impact_samples: list[Any] | None,
    impact_total_seen: int | None,
) -> list[str]:
    """Write the exact payloads and the bounded impact sample."""
    warnings: list[str] = []
    for index, entry in enumerate(payloads or [], start=1):
        if not isinstance(entry, dict):
            continue
        content = entry.get("content")
        if not isinstance(content, str) or not content.strip():
            continue
        try:
            bundle.record_payload(
                content,
                label=str(entry.get("label") or f"payload-{index}"),
                step=index,
                language=entry.get("language"),
                produced=str(entry.get("produced") or ""),
            )
        except (OSError, ValueError):
            logger.exception("could not store payload %d", index)
            warnings.append(f"Payload {index} could not be stored.")

    if impact_samples:
        try:
            bundle.record_impact(impact_samples, total_seen=impact_total_seen)
        except (OSError, ValueError):
            logger.exception("could not store impact sample")
            warnings.append("The impact sample could not be stored.")
    return warnings


def _seal(
    bundle: Any,
    *,
    report_id: str,
    title: str,
    severity: str,
    cvss_score: float,
    target: str,
    endpoint: str | None,
    method: str | None,
    cwe: str | None,
    cve: str | None,
    impact: str,
    http_exchange_ids: list[str] | None,
    evidence_files: list[str] | None,
) -> None:
    """Write the immutable ``finding.json`` the report renders from.

    The renderer cites this record rather than globbing the folder, so a report
    can never link to a file that is not there.
    """
    try:
        bundle.seal(
            {
                "id": report_id,
                "title": title,
                "severity": severity,
                "cvss": cvss_score,
                "target": target,
                "endpoint": endpoint,
                "method": method,
                "cwe": cwe,
                "cve": cve,
                "impact": impact,
                "http_exchange_ids": http_exchange_ids or [],
                "evidence_files": list(evidence_files or []),
            }
        )
    except (OSError, ValueError):
        logger.exception("could not seal evidence bundle for %s", report_id)


def _record_on_report(report_state: Any, report_id: str, bundle_dir: Path) -> None:
    """Point the finding at its bundle so the report renderer finds it."""
    try:
        report_state.attach_evidence_bundle(report_id, str(bundle_dir))
    except Exception:  # noqa: BLE001 - losing the pointer must not lose the finding
        logger.debug("could not record bundle for %s", report_id, exc_info=True)
