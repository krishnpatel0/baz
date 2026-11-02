"""Version fingerprinting — pin what is deployed before claiming a 1-day.

A CVE without a version is a hypothesis. This module turns fingerprint signals
into a version claim with a *source*, because the source changes how much the
claim is worth: a version read from a lockfile on the origin beats one scraped
from a `?ver=` query string, and the adjudicator treats them differently.

The failure mode this exists for is cached truth: the CDN is still serving
`jquery-3.4.1.min.js` weeks after the origin was patched. Every source here is
classified by whether it can lie about the present.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Source(StrEnum):
    """How the version was derived, most to least trustworthy."""

    LOCKFILE = "lockfile"
    """`composer.lock` / `package-lock.json` read from the origin."""
    CHANGELOG = "changelog"
    """A changelog or version file served by the app itself."""
    ASSET = "asset"
    """A versioned static asset fetched live (not from a query string)."""
    BEHAVIOUR = "behaviour"
    """A feature known to exist only in certain releases."""
    ENDPOINT = "endpoint"
    """A self-disclosing endpoint (`/server-status`, phpinfo)."""
    HEADER = "header"
    """`Server` / `X-Powered-By`. Distribution builds backport without bumping."""
    QUERY = "query"
    """`?ver=` style cache-busters. Can be stale for weeks."""
    GUESSED = "guessed"


_RELIABLE = {Source.LOCKFILE, Source.CHANGELOG, Source.ASSET, Source.BEHAVIOUR, Source.ENDPOINT}

# version-shaped strings worth capturing
_VERSION_RE = re.compile(
    r"""
    (?P<product>[A-Za-z][\w.-]{1,30}?)      # product name, non-greedy
    [ /v=-]+
    (?P<version>\d{1,4}(\.\d{1,4}){1,3})    # 1.2 / 1.2.3 / 1.2.3.4
    (?P<extra>[-._\w]*)                      # -beta1, .Final, +build
    """,
    re.VERBOSE,
)

# header names that commonly carry versions
_VERSION_HEADERS = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-drupal-cache",
    "x-generator",
    "x-version",
    "x-runtime",
)

# lockfiles map product -> JSON path of the version
_LOCKFILE_PATTERNS: dict[str, str] = {
    "composer.lock": "packages[].version",
    "package-lock.json": 'packages[""].version',
    "yarn.lock": None,  # format is not JSON; handled textually
    "Gemfile.lock": None,
    "poetry.lock": None,
    "requirements.txt": None,
}

_ASSET_VERSION_RE = re.compile(r"[\w.-]+-v?(\d{1,4}(?:\.\d{1,4}){1,3})(?:\.min)?\.(js|css)")

_QUERY_VERSION_RE = re.compile(r"[?&](?:ver|v|version)=(\d{1,4}(?:\.\d{1,4}){1,3})")

_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE
)


@dataclass(slots=True)
class Component:
    """One software component with a version claim and its provenance."""

    product: str
    version: str
    source: Source
    evidence: str
    """Where exactly the version came from — the URL or header line."""
    confidence: float = 0.5
    notes: str = ""

    @property
    def reliable(self) -> bool:
        return self.source in _RELIABLE

    def to_wire(self) -> dict[str, Any]:
        return {
            "product": self.product,
            "version": self.version,
            "source": str(self.source),
            "evidence": self.evidence,
            "confidence": self.confidence,
            "reliable": self.reliable,
            "notes": self.notes,
        }


@dataclass(slots=True)
class Fingerprint:
    """Everything one HTTP interaction said about the stack."""

    url: str
    components: list[Component] = field(default_factory=list)
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    generator: str = ""

    def to_wire(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "components": [c.to_wire() for c in self.components],
            "cookies": dict(self.cookies),
            "headers": dict(self.headers),
            "generator": self.generator,
        }


def from_headers(url: str, headers: dict[str, str]) -> Fingerprint:
    """Extract version claims from response headers.

    Headers are the weakest source: distributions backport security fixes into
    the same version string, so `Server: Apache/2.4.49` means *built from* 2.4.49,
    not *vulnerable as* 2.4.49. Everything found here is tagged accordingly.
    """
    fp = Fingerprint(url=url)
    lowered = {k.lower(): v for k, v in headers.items()}
    fp.headers = dict(lowered)

    for name in _VERSION_HEADERS:
        value = lowered.get(name)
        if not value:
            continue
        for match in _VERSION_RE.finditer(value):
            fp.components.append(
                Component(
                    product=match.group("product").strip(". -"),
                    version=match.group("version"),
                    source=Source.HEADER,
                    evidence=f"{name}: {value}",
                    confidence=0.3,
                    notes="distribution builds backport fixes without bumping the banner",
                )
            )

    for cookie in lowered.get("set-cookie", "").split(","):
        cname = cookie.split("=", 1)[0].strip().lower()
        if cname:
            fp.cookies[cname] = cname

    if gen := _GENERATOR_RE.search(str(headers.get("_body", ""))):
        fp.generator = gen.group(1)

    return fp


def from_html(url: str, body: str) -> list[Component]:  # noqa: ARG001
    """Version claims from versioned asset paths and query strings in HTML.

    These are the most common version signals on real sites and the easiest to
    get wrong: a `?ver=` parameter reflects whatever was current when the page
    template shipped, which can lag the origin by months. Both are tagged with
    their real source so callers can weigh them.
    """
    found: list[Component] = []
    seen: set[tuple[str, str]] = set()

    for match in _ASSET_VERSION_RE.finditer(body):
        version, ext = match.group(1), match.group(2)
        asset = match.group(0)
        product = asset.rsplit("-", 1)[0].rsplit("/", 1)[-1]
        key = (product, version)
        if key in seen:
            continue
        seen.add(key)
        found.append(
            Component(
                product=product,
                version=version,
                source=Source.ASSET,
                evidence=f"asset: {asset}",
                confidence=0.7,
                notes=f"versioned .{ext} asset; verify by fetching it live",
            )
        )

    for match in _QUERY_VERSION_RE.finditer(body):
        version = match.group(1)
        key = ("query-string", version)
        if key in seen:
            continue
        seen.add(key)
        found.append(
            Component(
                product="query-string",
                version=version,
                source=Source.QUERY,
                evidence=f"query: {match.group(0)}",
                confidence=0.2,
                notes="?ver= reflects page template age, not origin version; "
                "re-fetch the referenced asset to check",
            )
        )
    return found


def from_lockfile(name: str, body: str) -> list[Component]:
    """Components from a lockfile shipped to the origin.

    A lockfile is the strongest external signal — it is the build manifest —
    and also the easiest to over-read: `composer.lock` pins the direct
    dependency, and the vulnerable version may be a transitive one. Both facts
    go in the notes.
    """
    found: list[Component] = []
    if name in ("composer.lock", "package-lock.json"):
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return found
        if name == "composer.lock":
            found.extend(
                Component(
                    product=pkg.get("name", "?"),
                    version=pkg.get("version", "?"),
                    source=Source.LOCKFILE,
                    evidence=f"{name}: {pkg.get('name')}",
                    confidence=0.95,
                    notes="lockfile pin; transitive deps may differ from what is actually loaded",
                )
                for pkg in data.get("packages", []) + data.get("packages-dev", [])
            )
        else:
            for key, pkg in (data.get("packages") or {}).items():
                found.append(
                    Component(
                        product=pkg.get("name") or key,
                        version=pkg.get("version", "?"),
                        source=Source.LOCKFILE,
                        evidence=f"{name}: {pkg.get('name') or key}",
                        confidence=0.95,
                    )
                )
        return found

    # textual formats: requirements.txt, Gemfile.lock style
    line_re = re.compile(r"^\s*([A-Za-z0-9_.-]+)[=><~ ]+([\d][\w.]*)", re.MULTILINE)
    found.extend(
        Component(
            product=match.group(1),
            version=match.group(2),
            source=Source.LOCKFILE,
            evidence=f"{name}: {match.group(0).strip()}",
            confidence=0.9,
        )
        for match in line_re.finditer(body)
    )
    return found


def merge(*fingerprints: Fingerprint) -> list[Component]:
    """Combine claims, keeping the most reliable source per product.

    When two sources disagree, both are kept with the loser demoted in
    confidence — a disagreement is itself information (the cached-asset case),
    and silently picking one hides it.
    """
    by_product: dict[str, list[Component]] = {}
    for fp in fingerprints:
        for comp in fp.components:
            by_product.setdefault(comp.product.lower(), []).append(comp)

    merged: list[Component] = []
    for claims in by_product.values():
        claims.sort(key=lambda c: c.confidence, reverse=True)
        best = claims[0]
        if len(claims) > 1:
            others = [f"{c.source.value}:{c.version}" for c in claims[1:]]
            best.notes = (best.notes + "; " if best.notes else "") + (
                f"conflicting claims: {', '.join(others)}"
            )
            # disagreement lowers confidence in the winner too
            best.confidence = min(best.confidence, 0.6)
        merged.append(best)
    return sorted(merged, key=lambda c: (-c.confidence, c.product))
