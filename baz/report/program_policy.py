"""Program policy research — find out how *this* program rates things.

Adjudication needs a program's own opinion, and HackerOne says plainly that a
program "might use a scoring method other than CVSS ... outlined in their
guidelines". So the policy has to be looked up, not assumed.

What is realistic to obtain here, in descending order of reliability:

1. **Declared policy** — the agent read the program's guidelines during the
   engagement and recorded them (`program_severity_scale`,
   `program_out_of_scope`). Most reliable, because a human-equivalent read it.
2. **Known platform defaults** — Immunefi publishes a severity classification
   system; HackerOne/VHA use CVSS with program discretion. These are real
   baselines, not guesses, and they are baked in below.
3. **Nothing** — the program is unknown or private. Adjudication then runs
   without a policy and says so, rather than inventing one.

The layer never fabricates a scale. A missing policy is a stated gap; a made-up
one would be worse than no adjudication at all, because it reads as authoritative.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any


logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class KnownProgram:
    """A platform whose default taxonomy we can state accurately."""

    key: str
    label: str
    scale: dict[str, str]
    out_of_scope: tuple[str, ...]
    source: str
    note: str = ""


# Immunefi v2.3, Websites and Apps table, mapped onto our impact classes. The
# published taxonomy rates by *consequence*, so the mapping is from consequence
# to our class rather than from CVSS.
_IMMUNEFI_WEB = KnownProgram(
    key="immunefi",
    label="Immunefi (Websites and Apps, v2.3)",
    scale={
        "command_execution": "critical",
        "authentication_bypass": "critical",
        "cross_tenant_data": "high",
        "sensitive_data_exposure": "critical",
        "privilege_escalation": "critical",
        "financial_manipulation": "critical",
        "stored_injection": "high",
        "reflected_injection": "medium",
        "business_logic": "medium",
        "rate_limit": "low",
        "informational_disclosure": "low",
    },
    out_of_scope=(
        "self_xss",
        "config_hygiene",
        "informational_disclosure",
    ),
    source="https://immunefi.com/immunefi-vulnerability-severity-classification-system-v2-3/",
    note=(
        "Rated by demonstrated consequence. Out of scope by default: self-XSS, "
        "missing HTTP security headers, SPF/DMARC, non-confidential information "
        "disclosure, user enumeration, scanner output without impact."
    ),
)

# HackerOne itself does not publish a fixed scale — it delegates to CVSS or to the
# program. So this entry carries no overrides, only the honest statement that the
# program decides.
_HACKERONE = KnownProgram(
    key="hackerone",
    label="HackerOne (program-defined)",
    scale={},
    out_of_scope=(),
    source="https://docs.hackerone.com/en/articles/8475343-severity",
    note=(
        "HackerOne uses a custom CVSS 3.0, or CVSS 3.1/4.0, or a method of the "
        "program's own choosing — the program's guidelines win. No platform-wide "
        "overrides are applied here."
    ),
)

_KNOWN: dict[str, KnownProgram] = {
    "immunefi": _IMMUNEFI_WEB,
    "hackerone": _HACKERONE,
    "bugcrowd": KnownProgram(
        key="bugcrowd",
        label="Bugcrowd (VRT, program-defined)",
        scale={},
        out_of_scope=(),
        source="https://bugcrowd.com/vulnerability-rating-taxonomy",
        note="Bugcrowd uses its VRT with per-program priority overrides.",
    ),
}


def detect_platform(*hints: str) -> str:
    """Best-effort platform key from a URL, host, or free-text label."""
    haystack = " ".join(str(h) for h in hints if h).lower()
    for key in _KNOWN:
        if key in haystack:
            return key
    if "immunefi.com" in haystack:
        return "immunefi"
    return ""


def known_program(key: str) -> KnownProgram | None:
    return _KNOWN.get((key or "").lower())


def resolve_policy(report: dict[str, Any]) -> dict[str, Any]:
    """Derive the policy inputs for adjudication, stating where each came from.

    Returns a dict ready to hand to ``PolicyProfile`` plus a ``confidence`` and a
    ``gaps`` list, so a caller can tell "the program says X" from "the platform
    says X" from "nobody said anything".
    """
    declared_scale = report.get("program_severity_scale")
    declared_oos = report.get("program_out_of_scope")
    declared_source = str(report.get("program_policy_source") or "")

    if isinstance(declared_scale, dict) and declared_scale:
        return {
            "platform": str(report.get("platform") or "declared"),
            "custom_scale": {str(k): str(v) for k, v in declared_scale.items()},
            "out_of_scope_impacts": tuple(
                str(x) for x in (declared_oos or []) if isinstance(x, (str, int))
            ),
            "source": declared_source or "program guidelines (recorded during the engagement)",
            "confidence": "declared",
            "gaps": [] if declared_source else ["policy source URL not recorded"],
        }

    platform = detect_platform(
        str(report.get("platform") or ""),
        str(report.get("target") or ""),
        str(report.get("endpoint") or ""),
    )
    known = known_program(platform)
    if known is not None:
        gaps: list[str] = []
        if not known.scale:
            gaps.append(
                f"{known.label} does not publish a fixed scale; the program's own "
                "guidelines decide, and none were recorded for this run."
            )
        return {
            "platform": known.key,
            "custom_scale": dict(known.scale),
            "out_of_scope_impacts": known.out_of_scope,
            "source": known.source,
            "note": known.note,
            "confidence": "platform-default",
            "gaps": gaps,
        }

    return {
        "platform": "generic",
        "custom_scale": {},
        "out_of_scope_impacts": (),
        "source": "",
        "confidence": "none",
        "gaps": [
            "No program policy recorded and no known platform detected. Severity "
            "falls back to impact classification and CVSS only — check the "
            "program's own taxonomy before submitting."
        ],
    }


def describe(report: dict[str, Any]) -> str:
    """One-line human summary of the policy basis for a finding."""
    resolved = resolve_policy(report)
    source = resolved.get("source") or "no program policy"
    confidence = resolved["confidence"]
    line = f"policy: {confidence} ({source})"
    gaps = resolved.get("gaps") or []
    if gaps:
        line += f" — gap: {gaps[0]}"
    return line
