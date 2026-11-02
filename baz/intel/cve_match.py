"""CVE intelligence — match pinned versions to known-broken ranges.

`vulnx` (ProjectDiscovery's cvemap) is in the sandbox image and is the primary
lookup: it returns CVE ids, affected ranges when available, EPSS scores and
exploit references. This module wraps it, adds the range-and-precondition
checking that turns a CVE list into a work queue, and never claims a match it
cannot substantiate.

The rule that makes this useful rather than noisy: **a version match is not a
finding.** The output of this module is a prioritised queue of hypotheses, each
with the preconditions an agent must confirm before spending a turn.
"""

from __future__ import annotations

import contextlib
import json
import logging
import re
import shutil
from dataclasses import dataclass, field
from typing import Any

from packaging.version import Version


logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class CveRecord:
    """One CVE as returned by cvemap, normalised."""

    cve_id: str
    product: str
    summary: str = ""
    cvss: float | None = None
    epss: float | None = None
    affected: str = ""
    """The affected-version expression as the advisory states it."""
    references: tuple[str, ...] = ()
    has_poc: bool = False
    kev: bool = False
    """In CISA's Known Exploited Vulnerabilities catalog."""

    def to_wire(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "product": self.product,
            "summary": self.summary[:200],
            "cvss": self.cvss,
            "epss": self.epss,
            "affected": self.affected,
            "references": list(self.references)[:5],
            "has_poc": self.has_poc,
            "kev": self.kev,
        }


@dataclass(slots=True)
class Match:
    """A CVE matched to a component, with the work still to do."""

    component_product: str
    component_version: str
    record: CveRecord
    range_claimed: bool = False
    """True when the affected range was parseable and the version is inside it."""
    preconditions: list[str] = field(default_factory=list)
    """What must be true on the target before a PoC is worth firing."""

    def to_wire(self) -> dict[str, Any]:
        return {
            **self.record.to_wire(),
            "component_product": self.component_product,
            "component_version": self.component_version,
            "range_claimed": self.range_claimed,
            "preconditions": self.preconditions,
        }


def _vulnx_path() -> str | None:
    """vulnx lives in the sandbox, not on the host; callers pass results in.

    Kept for symmetry with the other lookups — host-side callers supply output,
    sandbox-side callers invoke the binary directly.
    """
    return shutil.which("vulnx")


def parse_cvemap_output(text: str) -> list[CveRecord]:
    """Parse `vulnx search --json` output into records, tolerating partial data.

    vulnx emits either a JSON array or newline-delimited objects (one per
    record) depending on flags; both are handled. Field names differ between
    the CVE and the KEV/TEMPLATE shapes, so every access is defensive and a
    malformed record is skipped rather than failing the batch.
    """
    records: list[CveRecord] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # vulnx --json with no array wrapper emits one object per line.
        items = []
        for raw_line in text.splitlines():
            stripped = raw_line.strip()
            if not stripped.startswith("{"):
                continue
            with contextlib.suppress(json.JSONDecodeError):
                items.append(json.loads(stripped))
        if not items:
            logger.debug("cvulnx output was neither JSON nor NDJSON")
            return _parse_cvemap_lines(text)
        data = items

    items = data if isinstance(data, list) else data.get("results", [])
    for item in items:
        if not isinstance(item, dict):
            continue
        # vulnx names the id `doc_id` for CVE-shaped records.
        cve_id = str(item.get("doc_id") or item.get("id") or item.get("cve_id") or "").upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve_id):
            continue
        records.append(
            CveRecord(
                cve_id=cve_id,
                # Field names are the live vulnx schema, verified against
                # `vulnx search --json`: cve_id, description, remediation,
                # cvss_score, epss_score, is_poc, is_kev, cwe_id. Earlier
                # guesses (doc_id/name/poc/kev) matched nothing and produced
                # an empty queue.
                product=_product_of(item),
                summary=str(item.get("description") or item.get("cve_description") or ""),
                cvss=_float(item.get("cvss_score") or item.get("cvss")),
                epss=_float(item.get("epss_score") or item.get("epss")),
                affected=str(item.get("affected") or item.get("affected_versions") or ""),
                references=tuple(
                    str(r) for r in (item.get("references") or item.get("urls") or [])[:10]
                ),
                has_poc=bool(item.get("is_poc") or item.get("poc")),
                kev=bool(item.get("is_kev") or item.get("kev")),
            )
        )
    return records


def _parse_cvemap_lines(text: str) -> list[CveRecord]:
    """Fallback for the table output when JSON is unavailable."""
    return [CveRecord(cve_id=m.group(1)) for m in re.finditer(r"(CVE-\d{4}-\d{4,7})", text)]


def _product_of(item: dict[str, Any]) -> str:
    """Best-effort product name from a vulnx record.

    vulnx records carry no dedicated product field. The description leads with
    it in practice — "Traefik 3.7.11 before 3.7.15 contains an authorization
    bypass" — so the first token before a version or a verb is the product.
    """
    for key in ("product", "vendor_product", "cpe_product", "package"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    for key in ("name", "title"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            head = re.split(r"[-:]", value, maxsplit=1)[0].strip()
            return re.sub(r"\s+\d.*$", "", head).lower()
    description = str(item.get("description") or "").strip()
    if not description:
        return ""
    # First 1-3 words, stopping at a version number, a lowercase verb, or
    # punctuation: "Traefik 3.7.11 before ..." -> "traefik".
    match = re.match(r"([A-Za-z][\w.+\- ]{1,40}?)(?=\s+\d|\s+[a-z]+\s|[,.:;]|$)", description)
    return match.group(1).strip().lower() if match else description.split()[0].lower()


def _float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


_RANGE_RE = re.compile(
    r"""
    (?P<low_op><=|<|>=|>)?\s*
    (?P<low>\d+(?:\.\d+)*)
    (?:\s*(?:to|-|\.\.)\s*
      (?P<high_op><=|<|>=|>)?\s*
      (?P<high>\d+(?:\.\d+)*)
    )?
    """,
    re.VERBOSE,
)


def version_in_range(version: str, affected: str) -> bool | None:
    """Whether ``version`` falls inside ``affected``, or None if unparseable.

    Handles the common advisory shapes: "2.0.0 - 2.14.1", "<= 2.14.1",
    ">= 1.0, < 2.15.0", and bare versions ("affected: 2.14.1 and below").
    Unknown shapes return None so callers treat the match as unconfirmed rather
    than claiming a range they did not actually check.
    """
    try:
        target = Version(_strip_extras(version))
    except (ImportError, ValueError):
        return None

    affected = affected.strip()
    if not affected:
        return None

    for match in _RANGE_RE.finditer(affected):
        low_op = match.group("low_op") or ""
        low = match.group("low")
        high = match.group("high")
        high_op = match.group("high_op") or ""

        lo = Version(low) if low else None
        hi = Version(high) if high else None

        inside = True
        if lo is not None:
            inside &= target >= lo if low_op in ("", ">=", ">") else target > lo
        if hi is not None:
            inside &= target <= hi if high_op in ("", "<=", "") else target < hi
        if inside:
            return True

    # bare version with no operator: "affected: 2.14.1" means exactly/that-line
    bare = re.search(r"\b(\d+(?:\.\d+)+)\b", affected)
    if bare:
        return target == Version(bare.group(1))
    return None


def _strip_extras(version: str) -> str:
    """Drop build metadata that breaks Version parsing: 2.14.1-Final -> 2.14.1."""
    return re.split(r"[-+]\w", version.strip())[0]


def prioritise(matches: list[Match]) -> list[Match]:
    """Order the work queue: exploitable-now first.

    KEV (actively exploited), then PoC availability, then EPSS, then CVSS. A
    critical with no PoC and low EPSS loses to a medium with a public exploit
    and a 90 EPSS — that ordering is the difference between a queue and a list.
    """

    def key(m: Match) -> tuple[int, int, float, float]:
        rec = m.record
        return (
            0 if rec.kev else 1,
            0 if rec.has_poc else 1,
            -(rec.epss or 0.0),
            -(rec.cvss or 0.0),
        )

    return sorted(matches, key=key)


def match_components(
    components: list[Any],
    records: list[CveRecord],
) -> list[Match]:
    """Match CVE records against fingerprinted components.

    ``components`` are :class:`baz.intel.fingerprint.Component`. A match is
    recorded even when the range could not be checked — it enters the queue as
    *unconfirmed* rather than being dropped, because the agent may confirm it
    from the advisory directly.
    """
    by_product: dict[str, list[Any]] = {}
    for comp in components:
        key = comp.product.lower().split("/")[-1]
        by_product.setdefault(key, []).append(comp)

    matches: list[Match] = []
    for record in records:
        product_key = record.product.lower().replace(" ", "-").split("/")[-1]
        candidates = []
        for key, comps in by_product.items():
            if key in product_key or product_key in key:
                candidates.extend(comps)
        for comp in candidates:
            in_range = version_in_range(comp.version, record.affected) if record.affected else None
            matches.append(
                Match(
                    component_product=comp.product,
                    component_version=comp.version,
                    record=record,
                    range_claimed=bool(in_range),
                    preconditions=_preconditions_for(record),
                )
            )
    return prioritise(matches)


_PRECONDITION_HINTS: tuple[tuple[str, str], ...] = (
    (r"debug|actuator|console", "debug/management endpoint must be exposed"),
    (r"webdav", "WebDAV must be enabled"),
    (r"deserializ|unserial", "a deserialization sink must accept attacker input"),
    (r"upload", "file upload must be reachable in scope"),
    (r"auth|login|credential", "valid credentials or a bypass are needed"),
    (r"template", "template editing must be reachable"),
    (r"proxy|cache", "the relevant cache/proxy must front the origin"),
)


def _preconditions_for(record: CveRecord) -> list[str]:
    """Preconditions to confirm before spending a turn on this CVE."""
    text = f"{record.summary} {record.affected}".lower()
    out = [hint for pattern, hint in _PRECONDITION_HINTS if re.search(pattern, text)]
    if not out:
        out = ["read the advisory: what must be enabled/exposed for this to fire?"]
    return out
