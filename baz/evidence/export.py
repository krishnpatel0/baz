"""Submission-shaped export — what a hunter actually pastes into a form.

Two platforms are targeted because their severity languages differ in a way that
matters, and a report written for one reads wrong on the other.

**HackerOne** asks for a narrative a triager can follow and re-run: title,
reproduction steps, expected vs actual, impact, supporting material. Severity is
attached separately from a program's own taxonomy.

**Immunefi** classifies almost entirely by *consequence* — "direct theft of any
user funds", "permanent freezing of funds" — with the CVSS vector as a secondary
input, and it downgrades or rejects on out-of-scope impacts (`self-XSS`,
`scanner report without demonstrated impact`, `missing HTTP security headers`,
`reflected plain text injection`). A report that ignores those rules reads as
unaware of the program.

So the exporter does not just reformat the same markdown twice. It re-frames the
finding in each platform's vocabulary, and it says so when a finding lands on an
Immunefi out-of-scope impact — better to tell the hunter before they submit than
to let the project tell them after.
"""

from __future__ import annotations

import json
import logging
import shutil
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)

EXPORT_DIRNAME = "submission"


@dataclass(slots=True)
class PlatformView:
    """How one platform should receive this finding."""

    name: str
    filename: str
    body: str
    warnings: list[str] = field(default_factory=list)


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _severity_word(report: dict[str, Any]) -> str:
    return str(report.get("severity") or "medium").strip().lower()


def _cvss(report: dict[str, Any]) -> str:
    score = report.get("cvss")
    return f"{score:.1f}" if isinstance(score, (int, float)) else "not scored"


def _bundle_items(report: dict[str, Any]) -> list[Path]:
    raw = report.get("evidence_bundle")
    if not isinstance(raw, str):
        return []
    root = Path(raw)
    if not root.is_dir():
        return []
    return sorted(p for p in root.rglob("*") if p.is_file())


# Impacts Immunefi lists as out of scope for Website/App programs. Checked against
# the v2.3 classification. Not exhaustive — a program may add its own — but these
# are the ones a report most often trips over.
_IMMUNEFI_OOS_SIGNALS: tuple[tuple[str, str], ...] = (
    ("self-xss", "self-XSS is out of scope by default on Immunefi"),
    ("missing header", "missing HTTP headers without demonstrated impact are out of scope"),
    ("missing http", "missing HTTP security headers without demonstrated impact are out of scope"),
    ("spf", "SPF/DMARC misconfiguration is out of scope by default"),
    ("dmarc", "SPF/DMARC misconfiguration is out of scope by default"),
    ("stack trace", "non-confidential server information disclosure is out of scope"),
    ("user enumeration", "user/tenant enumeration alone is out of scope"),
    ("scanner", "automated scanner output without demonstrated impact is out of scope"),
    ("logout", "logout-only CSRF has no state-modifying impact"),
    ("ssl", "lack of TLS best practice is out of scope"),
    ("tls configuration", "lack of TLS best practice is out of scope"),
)


def immunefi_warnings(report: dict[str, Any]) -> list[str]:
    """Flag findings that land on an Immunefi default out-of-scope impact."""
    haystack = " ".join(
        _text(report.get(key)).lower()
        for key in ("title", "description", "impact", "technical_analysis")
    )
    warnings: list[str] = []
    for needle, message in _IMMUNEFI_OOS_SIGNALS:
        if needle in haystack:
            warnings.append(message)
    if not _text(report.get("poc_script_code")) and not _text(report.get("reproduction")):
        warnings.append("no reproduction — Immunefi rejects theoretical impacts")
    return warnings


def render_hackerone(report: dict[str, Any]) -> PlatformView:
    """The narrative form a HackerOne triager reads and re-runs."""
    title = _text(report.get("title")) or "Untitled finding"
    lines: list[str] = [f"# {title}", ""]

    lines.extend(["## Summary", "", _text(report.get("description")) or "_none_", ""])

    lines.extend(["## Steps to Reproduce", ""])
    steps = _text(report.get("poc_description"))
    lines.append(steps or "_No step-by-step reproduction recorded._")
    lines.append("")

    if code := _text(report.get("poc_script_code")):
        lines.extend(["### Proof of concept", "", "```", code, "```", ""])

    lines.extend(["## Expected vs Actual", ""])
    if counter := _text(report.get("counterevidence")):
        lines.extend(["**Expected:** the control described below should prevent this.", ""])
        lines.extend([f"**Actual:** it does not. Counterevidence considered: {counter}", ""])
    else:
        lines.extend(["**Expected:** input rejected or neutralised.", "**Actual:** see above.", ""])

    lines.extend(["## Impact", "", _text(report.get("impact")) or "_none_", ""])

    if remediation := _text(report.get("remediation_steps")):
        lines.extend(["## Remediation", "", remediation, ""])

    lines.extend(["## Supporting Material", ""])
    items = _bundle_items(report)
    if items:
        root = Path(_text(report.get("evidence_bundle")))
        lines.extend(f"- `{p.relative_to(root).as_posix()}`" for p in items)
    else:
        lines.append("_No captured artifacts._")
    lines.append("")

    lines.extend(
        [
            "## Metadata",
            "",
            f"- Severity: **{_severity_word(report)}**",
            f"- CVSS: {_cvss(report)}",
            f"- CWE: {_text(report.get('cwe')) or 'n/a'}",
            f"- Endpoint: {_text(report.get('endpoint')) or 'n/a'}",
        ]
    )
    warnings: list[str] = []
    verification = report.get("verification")
    if isinstance(verification, dict):
        lines.append(f"- Verification: **{verification.get('outcome')}**")
        if verification.get("outcome") == "not_reproduced":
            warnings.append("did not survive fresh-sandbox re-verification; expect a dispute")
    return PlatformView("hackerone", "hackerone.md", "\n".join(lines).rstrip() + "\n", warnings)


def render_immunefi(report: dict[str, Any]) -> PlatformView:
    """The consequence-first form Immunefi classifies against."""
    title = _text(report.get("title")) or "Untitled finding"
    lines: list[str] = [f"# {title}", ""]

    lines.extend(
        [
            "## Severity",
            "",
            f"**{_severity_word(report).title()}** — CVSS {_cvss(report)}",
            "",
            "Immunefi classifies by demonstrated impact. The claimed impact below is",
            "stated as a consequence, not as a scanner category.",
            "",
        ]
    )

    lines.extend(["## Impact", "", _text(report.get("impact")) or "_none_", ""])
    lines.extend(["## Description", "", _text(report.get("description")) or "_none_", ""])

    lines.extend(["## Steps to Reproduce", ""])
    lines.append(_text(report.get("poc_description")) or "_No reproduction recorded._")
    lines.append("")
    if code := _text(report.get("poc_script_code")):
        lines.extend(["```", code, "```", ""])

    lines.extend(["## Proof of Concept", ""])
    repro = report.get("reproduction")
    if isinstance(repro, dict) and repro.get("script"):
        lines.extend(
            [
                "The harness executed the following and observed it succeed:",
                "",
                "```",
                str(repro["script"]),
                "```",
                "",
                f"- Verdict: `{repro.get('verdict')}`",
                "",
            ]
        )
    else:
        lines.extend(["_No executable reproduction recorded._", ""])

    lines.extend(["## Supporting Material", ""])
    items = _bundle_items(report)
    if items:
        root = Path(_text(report.get("evidence_bundle")))
        lines.extend(f"- `{p.relative_to(root).as_posix()}`" for p in items)
    else:
        lines.append("_No captured artifacts._")
    lines.append("")

    warnings = immunefi_warnings(report)
    if warnings:
        lines.extend(["## Program-Rule Cautions", ""])
        lines.extend(f"- {w}" for w in warnings)
        lines.append("")

    return PlatformView("immunefi", "immunefi.md", "\n".join(lines).rstrip() + "\n", warnings)


def export_finding(report: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """Write both platform views plus a zip of the artifacts.

    Returns a manifest of what was produced. Existing files are overwritten — the
    export is derived state, and a re-run after a revision should replace the old
    view rather than accumulate versions a hunter might paste by mistake.
    """
    finding_dir = out_dir / str(report.get("id") or "unknown")
    finding_dir.mkdir(parents=True, exist_ok=True)

    views = [render_hackerone(report), render_immunefi(report)]
    written: list[str] = []
    for view in views:
        path = finding_dir / view.filename
        path.write_text(view.body, encoding="utf-8")
        written.append(path.name)

    (finding_dir / "finding.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False, default=str) + "\n",
        encoding="utf-8",
    )
    written.append("finding.json")

    items = _bundle_items(report)
    if items:
        root = Path(_text(report.get("evidence_bundle")))
        archive = finding_dir / "assets.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in items:
                zf.write(path, arcname=path.relative_to(root).as_posix())
        written.append("assets.zip")

    return {
        "report_id": report.get("id"),
        "dir": str(finding_dir),
        "files": written,
        "warnings": [w for view in views for w in view.warnings],
    }


def export_run(reports: list[dict[str, Any]], run_dir: Path) -> dict[str, Any]:
    """Export every finding in a finished run."""
    out_dir = run_dir / EXPORT_DIRNAME
    if out_dir.exists():
        # Derived state: a stale export is worse than none, because it looks current.
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    exported = [export_finding(report, out_dir) for report in reports]
    index = {
        "findings": exported,
        "count": len(exported),
        "platforms": ["hackerone", "immunefi"],
    }
    (out_dir / "index.json").write_text(
        json.dumps(index, indent=2, ensure_ascii=False, default=str) + "\n", encoding="utf-8"
    )
    logger.info("exported %d findings to %s", len(exported), out_dir)
    return index
