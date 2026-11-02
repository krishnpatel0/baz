"""Severity adjudication — deciding what a program will actually pay for.

CVSS is a *technical* score. Programs pay on a different axis: business impact
inside their threat model, and their own written policy. The gap is where hunters
lose money.

Three concrete cases CVSS gets wrong for bounty work:

- **Self-XSS** scores as reflected XSS. Most programs reject it outright.
- **A stack trace** scores as information disclosure. Immunefi lists it as out of
  scope; most programs rate it None.
- **An IDOR on a staging host** scores as high. If the host is out of scope, it
  scores nothing.

So adjudication runs four inputs and reconciles them, in this order of authority:

1. **Program policy** — the program's own taxonomy. HackerOne states plainly that
   a program "might use a scoring method other than CVSS ... outlined in their
   guidelines", so policy outranks any calculator.
2. **Demonstrated impact** — what the exploit provably achieved. Not what it
   could lead to; the verifier already rejected unsupported claims.
3. **Technical score** — CVSS, as one input rather than the answer.
4. **Model judgment** — a reasoned read of the business context, which is the one
   thing the other three cannot supply: whether *this* asset matters to *this*
   business.

The output is never a silent overwrite. A finding keeps the severity it was filed
with, the adjudicated severity, and the reasoning for any difference — because a
hunter needs to see what changed and argue with it.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from baz.report.program_policy import resolve_policy


logger = logging.getLogger(__name__)


class Rating(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_ORDER = {
    Rating.NONE: 0,
    Rating.LOW: 1,
    Rating.MEDIUM: 2,
    Rating.HIGH: 3,
    Rating.CRITICAL: 4,
}


def rank(rating: str | Rating) -> int:
    try:
        return _ORDER[Rating(str(rating).lower())]
    except (ValueError, KeyError):
        return 2


def max_rating(*ratings: str | Rating) -> Rating:
    best = max(ratings, key=rank) if ratings else Rating.MEDIUM
    return Rating(str(best).lower())


def min_rating(*ratings: str | Rating) -> Rating:
    worst = min(ratings, key=rank) if ratings else Rating.MEDIUM
    return Rating(str(worst).lower())


def cvss_to_rating(score: float | None) -> Rating:
    """The CVSS v3 banding a program's calculator would produce."""
    if score is None:
        return Rating.MEDIUM
    if score >= 9.0:
        return Rating.CRITICAL
    if score >= 7.0:
        return Rating.HIGH
    if score >= 4.0:
        return Rating.MEDIUM
    if score > 0.0:
        return Rating.LOW
    return Rating.NONE


@dataclass(slots=True)
class ImpactClass:
    """A recognised impact shape and how programs normally treat it."""

    name: str
    rating: Rating
    patterns: tuple[str, ...]
    rationale: str
    disqualifying: str = ""
    """When set, many programs reject outright regardless of CVSS."""


# Ordered most-severe first: the first match that is disqualifying wins, so a
# finding is not upgraded by a phrase that merely co-occurs with a rejectable one.
IMPACT_CLASSES: tuple[ImpactClass, ...] = (
    ImpactClass(
        "command_execution",
        Rating.CRITICAL,
        (
            "remote code execution",
            "rce",
            "arbitrary command",
            "command execution",
            "shell access",
            "code execution",
        ),
        "Server-side code execution: full control of the host and its data.",
    ),
    ImpactClass(
        "authentication_bypass",
        Rating.HIGH,
        (
            "authentication bypass",
            "auth bypass",
            "login as any",
            "forgot password bypass",
            "account takeover",
            "ato",
        ),
        "Can act as another user without their credentials.",
    ),
    ImpactClass(
        "cross_tenant_data",
        Rating.HIGH,
        (
            "cross-tenant",
            "cross tenant",
            "another tenant",
            "other user's data",
            "other users' data",
            "other user data",
            "idor",
            "bola",
            "horizontal privilege",
        ),
        "Reads or writes another party's data: a confidentiality or integrity breach "
        "across a boundary the product promises.",
    ),
    ImpactClass(
        "sensitive_data_exposure",
        Rating.HIGH,
        (
            "password hash",
            "credential",
            "api key",
            "private key",
            "pii",
            "personal data",
            "card number",
            "database dump",
            "full database",
        ),
        "Exposes secrets or regulated personal data, which carries disclosure "
        "obligations beyond the technical impact.",
    ),
    ImpactClass(
        "stored_injection",
        Rating.HIGH,
        ("stored xss", "persistent xss", "stored html injection"),
        "Persistent script execution in other users' browsers.",
    ),
    ImpactClass(
        "privilege_escalation",
        Rating.HIGH,
        (
            "privilege escalation",
            "privesc",
            "become admin",
            "escalate to admin",
            "vertical privilege",
        ),
        "Raises an attacker's authority inside the product.",
    ),
    ImpactClass(
        "financial_manipulation",
        Rating.HIGH,
        (
            "price manipulation",
            "payment bypass",
            "double spend",
            "double-spend",
            "free purchase",
            "funds transfer",
            "balance manipulation",
        ),
        "Direct monetary loss or unauthorized value transfer.",
    ),
    ImpactClass(
        "ssrf_internal",
        Rating.HIGH,
        (
            "ssrf",
            "server-side request forgery",
            "internal network",
            "metadata endpoint",
            "169.254.169.254",
            "cloud metadata",
        ),
        "Reaches internal services or cloud credentials from the server side.",
    ),
    ImpactClass(
        "reflected_injection",
        Rating.MEDIUM,
        ("reflected xss", "reflected html injection", "open redirect"),
        "Requires the victim to follow a crafted link; real, but bounded by user interaction.",
    ),
    ImpactClass(
        "business_logic",
        Rating.MEDIUM,
        (
            "business logic",
            "workflow bypass",
            "race condition",
            "coupon",
            "discount abuse",
            "enumeration",
        ),
        "Abuses intended functionality; value depends heavily on the program's "
        "product and its threat model.",
    ),
    ImpactClass(
        "rate_limit",
        Rating.LOW,
        ("rate limit", "brute force", "no throttling", "captcha bypass"),
        "Weakens a control without demonstrating the outcome it protects.",
    ),
    ImpactClass(
        "self_xss",
        Rating.NONE,
        ("self-xss", "self xss"),
        "Requires the victim to attack themselves; near-universally rejected.",
        "self-XSS is out of scope on most programs",
    ),
    ImpactClass(
        "config_hygiene",
        Rating.NONE,
        (
            "missing header",
            "missing security header",
            "hsts",
            "spf",
            "dmarc",
            "tls configuration",
            "cookie flag",
            "httponly",
            "x-frame-options",
            "banner disclosure",
            "server version",
        ),
        "Configuration hygiene without demonstrated impact.",
        "missing headers and email/DNS hygiene are commonly out of scope",
    ),
    ImpactClass(
        "informational_disclosure",
        Rating.LOW,
        (
            "stack trace",
            "error message",
            "internal ip",
            "server name",
            "source map",
            "directory listing",
        ),
        "Discloses non-confidential operational detail.",
        "non-confidential server information is out of scope on many programs",
    ),
)


@dataclass(slots=True)
class PolicyProfile:
    """A program's severity policy, as far as it is known."""

    platform: str = "generic"
    custom_scale: dict[str, str] = field(default_factory=dict)
    """Mapping from impact name to the program's own rating word."""

    out_of_scope_impacts: tuple[str, ...] = ()
    notes: str = ""
    source: str = ""

    def override_for(self, impact_name: str) -> Rating | None:
        value = self.custom_scale.get(impact_name)
        if value is None:
            return None
        try:
            return Rating(value.lower())
        except ValueError:
            return None


def classify_impact(text: str) -> list[ImpactClass]:
    """Every impact shape the finding's language matches, in table order."""
    haystack = text.lower()
    return [impact for impact in IMPACT_CLASSES if any(p in haystack for p in impact.patterns)]


@dataclass(slots=True)
class Adjudication:
    filed: Rating
    cvss_rating: Rating
    impact_rating: Rating
    final: Rating
    impacts: list[str] = field(default_factory=list)
    disqualifiers: list[str] = field(default_factory=list)
    rationale: list[str] = field(default_factory=list)
    policy_source: str = ""

    @property
    def changed(self) -> bool:
        return self.final is not self.filed

    @property
    def direction(self) -> str:
        if self.final is self.filed:
            return "unchanged"
        return "raised" if rank(self.final) > rank(self.filed) else "lowered"

    def to_wire(self) -> dict[str, Any]:
        return {
            "filed": str(self.filed),
            "cvss_rating": str(self.cvss_rating),
            "impact_rating": str(self.impact_rating),
            "final": str(self.final),
            "changed": self.changed,
            "direction": self.direction,
            "impacts": self.impacts,
            "disqualifiers": self.disqualifiers,
            "rationale": self.rationale,
            "policy_source": self.policy_source,
        }


def adjudicate(  # noqa: PLR0912
    report: dict[str, Any],
    *,
    policy: PolicyProfile | None = None,
    model_rating: str | None = None,
    model_reasoning: str = "",
) -> Adjudication:
    """Reconcile CVSS, demonstrated impact, program policy and model judgment.

    ``model_rating`` is the model's own read after seeing the evidence; it can
    raise a finding above what the rules allow (business context the rules cannot
    see) but cannot lower one below a disqualifier. A program that rejects
    self-XSS rejects it whatever the model thinks it is worth.
    """
    policy = policy or PolicyProfile()

    filed = Rating(str(report.get("severity") or "medium").lower())
    raw_cvss = report.get("cvss")
    cvss_rating = cvss_to_rating(raw_cvss if isinstance(raw_cvss, (int, float)) else None)

    text = " ".join(
        str(report.get(key) or "")
        for key in ("title", "description", "impact", "technical_analysis")
    )
    impacts = classify_impact(text)
    disqualifiers = [f"{i.name}: {i.disqualifying}" for i in impacts if i.disqualifying]

    if impacts:
        # A disqualifier caps the finding; otherwise the most severe matched
        # impact class sets the floor, because severity is about the worst thing
        # that was demonstrated, not the average of what was described.
        impact_rating = (
            min_rating(*(i.rating for i in impacts))
            if disqualifiers
            else max_rating(*(i.rating for i in impacts))
        )
    else:
        impact_rating = cvss_rating

    rationale: list[str] = [
        f"CVSS {report.get('cvss', 'unscored')} bands as {cvss_rating}.",
    ]
    if impacts:
        rationale.append(
            "Demonstrated impact reads as "
            + ", ".join(i.name for i in impacts)
            + f" → {impact_rating}."
        )
    else:
        rationale.append(
            "No recognised impact shape in the finding text; impact not established "
            "beyond the CVSS band."
        )

    final = max_rating(impact_rating, cvss_rating) if not impacts else impact_rating

    # Policy outranks everything, in both directions.
    if policy.custom_scale:
        overrides = [policy.override_for(i.name) for i in impacts]
        usable = [o for o in overrides if o is not None]
        if usable:
            final = min_rating(final, *usable) if disqualifiers else max_rating(*usable)
            rationale.append(
                f"Program policy maps this impact to {final}"
                + (f" (source: {policy.source})" if policy.source else "")
                + "."
            )

    if disqualifiers:
        rationale.append("Program-rule cautions: " + "; ".join(disqualifiers) + ".")

    if model_rating:
        try:
            candidate = Rating(model_rating.lower())
        except ValueError:
            candidate = final
        else:
            if not disqualifiers:
                # The model may see business context the rules cannot.
                final = max_rating(final, candidate)
            if model_reasoning:
                rationale.append(f"Model assessment: {model_reasoning}")
            if candidate is not final:
                rationale.append(
                    f"Model proposed {candidate}; held at {final} because the impact "
                    "classification sets a floor."
                )

    if rank(final) != rank(filed):
        direction = "raised" if rank(final) > rank(filed) else "lowered"
        rationale.append(f"Filed as {filed}, adjudicated {final} ({direction}).")
    else:
        rationale.append(f"Filed severity {filed} confirmed.")

    return Adjudication(
        filed=filed,
        cvss_rating=cvss_rating,
        impact_rating=impact_rating,
        final=final,
        impacts=[i.name for i in impacts],
        disqualifiers=disqualifiers,
        rationale=rationale,
        policy_source=policy.source,
    )


_PROGRAM_HINT = re.compile(r"(?i)https?://([a-z0-9.-]+)|(?:program|platform)[:=]\s*(\S+)")


def policy_from_report(report: dict[str, Any]) -> PolicyProfile:
    """Program profile for a finding: declared first, then platform default.

    Delegates to :mod:`baz.report.program_policy`, which knows which platforms
    publish a real taxonomy (Immunefi does) and which delegate to the program
    (HackerOne does). When neither applies the profile is empty and adjudication
    says so rather than inventing a scale.
    """
    resolved = resolve_policy(report)
    return PolicyProfile(
        platform=str(resolved.get("platform") or "generic"),
        custom_scale=dict(resolved.get("custom_scale") or {}),
        out_of_scope_impacts=tuple(resolved.get("out_of_scope_impacts") or ()),
        source=str(resolved.get("source") or ""),
        notes=str(resolved.get("note") or ""),
    )


def apply_adjudication(report: dict[str, Any], result: Adjudication) -> None:
    """Stamp the adjudication onto a finding without erasing the original.

    ``severity`` becomes the adjudicated value because that is what the program
    reads; ``severity_filed`` keeps what the agent claimed so a hunter can see
    and contest the change.
    """
    report.setdefault("severity_filed", str(result.filed))
    report["severity"] = str(result.final)
    report["severity_adjudication"] = result.to_wire()
