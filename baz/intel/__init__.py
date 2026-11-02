"""1-day intel engine: fingerprint -> pin -> match -> queue."""

from __future__ import annotations

from baz.intel.cve_match import (
    CveRecord,
    Match,
    match_components,
    parse_cvemap_output,
    prioritise,
    version_in_range,
)
from baz.intel.fingerprint import (
    Component,
    Fingerprint,
    Source,
    from_headers,
    from_html,
    from_lockfile,
    merge,
)


__all__ = [
    "Component",
    "CveRecord",
    "Fingerprint",
    "Match",
    "Source",
    "from_headers",
    "from_html",
    "from_lockfile",
    "match_components",
    "merge",
    "parse_cvemap_output",
    "prioritise",
    "version_in_range",
]
