"""Tech-stack detection — structured fingerprints, not prose guesses.

The 1-day engine needs a component and a version before it can do anything. This
module produces both from what a target already sent: response headers, cookie
names, HTML asset paths, generator tags, error shapes.

Design rules learned from the fingerprint module upstream of this:

**Two signals before a claim.** A `Server: nginx` header alone is a guess. Nginx
plus `X-Powered-By: Express` plus a `connect.sid` cookie is a stack. Claims
carry the signals that produced them so a caller can weigh them.

**Version is separate from product.** "They run WordPress" and "they run
WordPress 6.4.2" are different findings with different value. Plenty of targets
disclose the product and hide the version; the output has to represent that.

**Never invent a version.** A missing version is reported as missing. A made-up
`1.0` would flow straight into a CVE range check and produce a false 1-day.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any


logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class Signal:
    """One piece of evidence for a component claim."""

    kind: str
    """``header`` | ``cookie`` | ``asset`` | ``generator`` | ``body`` | ``error``."""

    value: str
    weight: float
    """How much this signal alone establishes the claim: 1.0 is definitive."""


@dataclass(slots=True)
class Tech:
    """A detected component, with the evidence and a separate version claim."""

    product: str
    category: str
    """``server`` | ``framework`` | ``cms`` | ``language`` | ``js`` | ``cdn`` |
    ``waf`` | ``database`` | ``proxy`` | ``analytics``."""

    confidence: float = 0.0
    version: str = ""
    version_source: str = ""
    signals: list[Signal] = field(default_factory=list)
    notes: str = ""

    @property
    def strong(self) -> bool:
        return self.confidence >= 0.7

    def to_wire(self) -> dict[str, Any]:
        return {
            "product": self.product,
            "category": self.category,
            "confidence": round(self.confidence, 2),
            "version": self.version,
            "version_source": self.version_source,
            "signals": [{"kind": s.kind, "value": s.value[:80]} for s in self.signals],
            "notes": self.notes,
        }


# --- rules -----------------------------------------------------------------
# (product, category, header_regex, weight). Matched against the whole header
# block so ordering and casing do not matter.

_HEADER_RULES: tuple[tuple[str, str, str, float], ...] = (
    ("nginx", "server", r"\bserver:\s*nginx(?:/([\d.]+))?", 0.9),
    ("apache", "server", r"\bserver:\s*apache(?:/([\d.]+))?", 0.9),
    ("iis", "server", r"\bserver:\s*microsoft-iis(?:/([\d.]+))?", 0.9),
    ("caddy", "server", r"\bserver:\s*caddy", 0.9),
    ("google-frontend", "server", r"\bserver:\s*gws", 0.7),
    ("tomcat", "server", r"\bserver:\s*apache-coyote", 0.85),
    ("jetty", "server", r"\bserver:\s*jetty", 0.85),
    ("openresty", "server", r"\bserver:\s*openresty", 0.85),
    ("cloudflare", "cdn", r"\bserver:\s*cloudflare\b|cf-ray:", 0.95),
    ("akamai", "cdn", r"\bakamai|x-akamai", 0.9),
    ("fastly", "cdn", r"\bx-served-by:\s*cache-|x-fastly", 0.9),
    ("cloudfront", "cdn", r"\bx-amz-cf-id|x-cache:\s*hit from cloudfront", 0.9),
    ("php", "language", r"\bx-powered-by:\s*php/([\d.]+)", 0.95),
    ("aspnet", "language", r"\bx-aspnet-version:\s*([\d.]+)|x-powered-by:\s*asp\.net", 0.95),
    ("express", "framework", r"\bx-powered-by:\s*express", 0.95),
    ("nextjs", "framework", r"\bx-powered-by:\s*next\.js|x-nextjs", 0.9),
    ("django", "framework", r"\bx-frame-options:\s*deny.*\bcsrf", 0.4),
    ("rails", "framework", r"\bx-runtime:.*\bx-request-id:|_session_id=.*rails", 0.6),
    ("laravel", "framework", r"\blaravel_session", 0.85),
    ("spring", "framework", r"\bjsessionid", 0.5),
    ("shopify", "cms", r"\bx-shopid|x-shopify-stage|shopify", 0.95),
    ("wordpress", "cms", r"\bx-powered-by:\s*wordpress|wp-", 0.7),
    ("drupal", "cms", r"\bx-generator:\s*drupal|x-drupal", 0.95),
    ("joomla", "cms", r"\bjoomla|jsid=", 0.7),
    ("grafana", "product", r"\bgrafana_session", 0.9),
    ("jenkins", "product", r"\bjsessionid.*jenkins|x-jenkins", 0.8),
    ("gitlab", "product", r"\b_gitlab_session|gitlab", 0.8),
    ("keycloak", "product", r"\bkeycloak", 0.85),
    ("auth0", "product", r"\bauth0", 0.7),
    ("firebase", "product", r"\bfirebase", 0.6),
    ("varnish", "proxy", r"\bvia:.*varnish|x-varnish", 0.9),
    ("haproxy", "proxy", r"\bx-served-by:\s*.*haproxy", 0.7),
    ("envoy", "proxy", r"\bserver:\s*envoy|x-envoy", 0.9),
    ("traefik", "proxy", r"\bserver:\s*traefik", 0.9),
    ("kong", "proxy", r"\bx-kong", 0.9),
    ("wordfence", "waf", r"\bwordfence", 0.8),
    ("sucuri", "waf", r"\bx-sucuri-id|sucuri", 0.9),
    ("imperva", "waf", r"\bx-iinfo|incapsula", 0.9),
    ("aws-waf", "waf", r"\bawselb|x-amzn-waf", 0.7),
    ("datadog", "analytics", r"\bdd-trace|x-datadog", 0.7),
    ("newrelic", "analytics", r"\bx-newrelic|newrelic", 0.6),
)

# Cookie names are the most reliable external signal: they come from the app's
# own session layer and are rarely scrubbed when headers are.
_COOKIE_RULES: tuple[tuple[str, str, str, float], ...] = (
    ("php", "language", r"^phpsessid$", 0.95),
    ("aspnet", "language", r"^asp\.net_sessionid$", 0.95),
    ("jsessionid", "framework", r"^jsessionid$", 0.9),
    ("laravel", "framework", r"^laravel_session$", 0.95),
    ("django", "framework", r"^csrftoken$|^sessionid$", 0.6),
    ("rails", "framework", r"^_[a-z0-9_]+_session$", 0.6),
    ("express", "framework", r"^connect\.sid$", 0.95),
    ("nextjs", "framework", r"^__next", 0.6),
    ("wordpress", "cms", r"^wordpress_|^wp-settings", 0.95),
    ("drupal", "cms", r"^ssess|^drupal", 0.9),
    ("shopify", "cms", r"^_shopify", 0.95),
    ("grafana", "product", r"^grafana_session", 0.95),
    ("gitlab", "product", r"^_gitlab_session", 0.95),
    ("keycloak", "product", r"^keycloak", 0.9),
    ("cloudflare", "cdn", r"^__cf_bm$|^cf_clearance$", 0.95),
    ("aws-alb", "proxy", r"^awsalb", 0.9),
    ("azure-appservice", "proxy", r"^arraffinity", 0.9),
)

# Versioned asset paths — the most common way a version leaks on a modern site.
_ASSET_RULES: tuple[tuple[str, str, str], ...] = (
    ("jquery", "js", r"jquery[-.](\d+\.\d+\.\d+)"),
    ("bootstrap", "js", r"bootstrap[-.](\d+\.\d+\.\d+)"),
    ("react", "js", r"react[-.@](\d+\.\d+\.\d+)"),
    ("angular", "js", r"angular[-.](\d+\.\d+\.\d+)"),
    ("vue", "js", r"vue[-.](\d+\.\d+\.\d+)"),
    ("moment", "js", r"moment[-.](\d+\.\d+\.\d+)"),
    ("lodash", "js", r"lodash[-.](\d+\.\d+\.\d+)"),
    ("tinymce", "js", r"tinymce[-./](\d+\.\d+\.\d+)"),
    ("ckeditor", "js", r"ckeditor[-./](\d+\.\d+\.\d+)"),
    ("swagger-ui", "js", r"swagger-ui[-.](\d+\.\d+\.\d+)"),
)

_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE
)

# Error shapes and body markers that identify a stack without any header.
_BODY_RULES: tuple[tuple[str, str, str, float], ...] = (
    ("wordpress", "cms", r"/wp-content/|/wp-includes/", 0.95),
    ("drupal", "cms", r"/sites/default/|Drupal\.settings", 0.9),
    ("joomla", "cms", r"/components/com_|/media/jui/", 0.9),
    ("nextjs", "framework", r"__NEXT_DATA__|/_next/static/", 0.95),
    ("nuxt", "framework", r"__NUXT__|/_nuxt/", 0.9),
    ("gatsby", "framework", r"/page-data/|___gatsby", 0.85),
    ("react", "js", r"data-reactroot|__REACT_DEVTOOLS", 0.7),
    ("vue", "js", r"data-v-[0-9a-f]{8}|__VUE__", 0.7),
    ("angular", "js", r"ng-version=|ng-app", 0.8),
    ("aspnet-mvc", "framework", r"__RequestVerificationToken|\.aspx", 0.7),
    ("laravel", "framework", r"laravel|csrf-token", 0.4),
    ("django", "framework", r"csrfmiddlewaretoken", 0.7),
    ("rails", "framework", r"authenticity_token|csrf-token.*rails", 0.5),
    ("codeigniter", "framework", r"ci_session", 0.6),
    ("firebase", "product", r"firebaseConfig|firebaseio\.com", 0.8),
    ("supabase", "product", r"supabase\.co|supabaseKey", 0.8),
    ("sentry", "analytics", r"sentry\.io|__SENTRY__", 0.6),
    ("stripe", "payment", r"js\.stripe\.com|pk_live_", 0.8),
    ("recaptcha", "waf", r"google\.com/recaptcha|g-recaptcha", 0.7),
    ("cloudflare-turnstile", "waf", r"challenges\.cloudflare\.com/turnstile", 0.8),
    ("hcaptcha", "waf", r"hcaptcha\.com", 0.8),
)

_JS_VERSION_RE = re.compile(r'"?version"?\s*[:=]\s*"(\d+\.\d+(?:\.\d+)?)"')

_SERVER_HEADER_VERSION = re.compile(r"(?:server|x-powered-by):\s*[\w.-]+/([\d.]+)", re.IGNORECASE)


def detect(  # noqa: PLR0912
    *,
    headers: dict[str, str] | None = None,
    body: str = "",
    url: str = "",  # noqa: ARG001 - kept for call-site symmetry with the other detectors
) -> list[Tech]:
    """Detect components from one response.

    ``headers`` should be lowercased keys. ``body`` is the response HTML (bounded
    by the caller — 256 KB is plenty; assets and meta tags are near the top).
    """
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    header_blob = "\n".join(f"{k}: {v}" for k, v in headers.items())
    cookie_blob = headers.get("set-cookie", "")
    found: dict[str, Tech] = {}

    def add(
        product: str,
        category: str,
        weight: float,
        kind: str,
        value: str,
        version: str = "",
        version_source: str = "",
    ) -> None:
        tech = found.get(product)
        if tech is None:
            tech = found[product] = Tech(product=product, category=category)
        tech.signals.append(Signal(kind=kind, value=value, weight=weight))
        # Independent signals combine: two 0.6s make 0.84, not 1.2.
        combined = 1.0
        for signal in tech.signals:
            combined *= 1.0 - signal.weight
        tech.confidence = round(1.0 - combined, 3)
        if version and not tech.version:
            tech.version = version
            tech.version_source = version_source

    for product, category, pattern, weight in _HEADER_RULES:
        match = re.search(pattern, header_blob, re.IGNORECASE)
        if match:
            version = ""
            if match.lastindex:
                version = match.group(1) or ""
            add(
                product,
                category,
                weight,
                "header",
                match.group(0)[:80],
                version,
                "header" if version else "",
            )

    for product, category, pattern, weight in _COOKIE_RULES:
        for cookie in cookie_blob.split(","):
            name = cookie.split("=", 1)[0].strip().lower()
            if name and re.search(pattern, name, re.IGNORECASE):
                add(product, category, weight, "cookie", name)
                break

    for product, category, pattern in _ASSET_RULES:
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            add(product, category, 0.7, "asset", match.group(0)[:60], match.group(1), "asset")

    if generator := _GENERATOR_RE.search(body):
        content = generator.group(1)
        product = " ".join(content.split()[:1]).lower() or "unknown-generator"
        version_match = re.search(r"(\d+\.\d+(?:\.\d+)?)", content)
        add(
            product,
            "cms",
            0.9,
            "generator",
            content[:60],
            version_match.group(1) if version_match else "",
            "generator",
        )

    for product, category, pattern, weight in _BODY_RULES:
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            add(product, category, weight, "body", match.group(0)[:60])

    # A framework version often sits in an inline config blob.
    if js_version := _JS_VERSION_RE.search(body):
        for tech in found.values():
            if tech.category in ("js", "framework") and not tech.version:
                tech.version = js_version.group(1)
                tech.version_source = "body:inline-config"
                break

    return sorted(found.values(), key=lambda t: -t.confidence)


def to_components(techs: list[Tech]) -> list[dict[str, str]]:
    """Shape for :func:`baz.intel.cve_match.match_components`.

    Only components with a version are useful to CVE matching, but all are
    returned so the caller can report "product known, version unknown" rather
    than silently dropping it.
    """
    return [
        {
            "product": t.product,
            "version": t.version,
            "source": t.version_source or "guessed",
            "evidence": "; ".join(s.value for s in t.signals[:3]),
        }
        for t in techs
    ]


def summary(techs: list[Tech]) -> str:
    """One-line stack summary for a report or a scan note."""
    if not techs:
        return "no components identified"
    parts = []
    for tech in techs[:8]:
        if tech.version:
            parts.append(f"{tech.product} {tech.version}")
        elif tech.strong:
            parts.append(tech.product)
    return ", ".join(parts) or "no high-confidence components"
