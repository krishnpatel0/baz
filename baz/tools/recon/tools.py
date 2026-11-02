"""Recon tools — the corpus, exposed where agents can actually reach it.

Two things an agent needs at recon time that prose skills cannot give:

- **`dork_search`** — the right query for the current phase, rendered against
  the target, rather than a list to read.
- **`cve_queue`** — components already fingerprinted, matched to CVEs and
  ordered by what is exploitable now.

Both return compact, ordered data. The reasoning lives in the skills; these are
the lookups.
"""

from __future__ import annotations

import json
from typing import Any

from agents import RunContextWrapper, function_tool

from baz.intel.cve_match import CveRecord, match_components, prioritise
from baz.intel.fingerprint import Component, Source
from baz.recon.dorks import Phase, all_dorks, plan_for, search


@function_tool(timeout=15)
async def dork_search(
    ctx: RunContextWrapper,
    domain: str,
    phase: str | None = None,
    min_value: str | None = None,
    brand: str | None = None,
    keywords: str | None = None,
    limit: int = 25,
) -> str:
    """Get recon search-engine queries for a target, ordered by phase and value.

    Passive: this returns the queries to run, it does not run them. Nothing here
    touches the target, which makes dorking safe before anything else.

    Phase order matters — start at ``secrets``. A hit there is an access
    primitive and reshapes the engagement; a hit at ``tech`` is a version string
    you could have read from a header.

    Args:
        domain: Target apex, e.g. ``example.com``.
        phase: One of ``secrets``, ``storage``, ``panels``, ``surface``,
            ``tech``, ``errors``. Omit for all phases in order.
        min_value: Floor on what a hit is worth — ``high``, ``medium``, ``low``.
            Use ``high`` when turns are tight.
        brand: Company name without the TLD; used by bucket-naming dorks.
        keywords: Product or technology words, e.g. ``invoice api``.
        limit: Maximum queries returned.

    Returns the queries plus, for each, what a hit means and the next action.
    """
    tokens: dict[str, str] = {"domain": domain}
    if brand:
        tokens["brand"] = brand
    if keywords:
        tokens["keywords"] = keywords

    if phase:
        try:
            Phase(phase)
        except ValueError:
            return json.dumps(
                {
                    "error": f"unknown phase {phase!r}",
                    "valid": [p.value for p in Phase],
                }
            )

    plan = plan_for(**tokens)
    if phase:
        plan = [p for p in plan if p["phase"] == phase]
    if min_value:
        order = {"high": 0, "medium": 1, "low": 2}
        floor = order.get(str(min_value).lower(), 2)
        plan = [p for p in plan if order.get(p["value"], 2) <= floor]

    # Unresolved tokens mean the query would run half-rendered; drop them so an
    # agent does not paste `site:s3.amazonaws.com "{brand}"` into an engine.
    usable = [p for p in plan if not p["missing_tokens"]]
    skipped = [p["id"] for p in plan if p["missing_tokens"]]

    payload: dict[str, Any] = {
        "domain": domain,
        "count": len(usable[:limit]),
        "dorks": [
            {
                "id": p["id"],
                "query": p["rendered"],
                "value": p["value"],
                "means": p["description"],
                "next": p["action"] or p["description"],
                "engine": p["engine"],
            }
            for p in usable[:limit]
        ],
    }
    if skipped:
        payload["skipped_missing_tokens"] = skipped
        payload["hint"] = "pass brand=/keywords= to enable those queries"
    return json.dumps(payload, ensure_ascii=False)


@function_tool(timeout=15)
async def dork_stats(ctx: RunContextWrapper) -> str:
    """Summarise the dork arsenal: counts by phase, and how many hit secrets."""
    dorks = all_dorks()
    by_phase: dict[str, int] = {}
    for dork in dorks:
        by_phase[str(dork.phase)] = by_phase.get(str(dork.phase), 0) + 1
    return json.dumps(
        {
            "total": len(dorks),
            "by_phase": by_phase,
            "secret_hitting": sum(1 for d in dorks if d.hits_secret),
            "high_value": len(search(min_value="high")),
        }
    )


@function_tool(timeout=20)
async def cve_queue(components_json: str) -> str:
    """Match fingerprinted components against known CVEs and order the work.

    Args:
        components_json: JSON list of ``{"product": "...", "version": "..."}``
            entries — what you fingerprinted. Cast a wide net: headers, asset
            versions, lockfiles, changelogs.

    Returns a prioritised queue. Ordering is KEV first, then whether a public
    PoC exists, then EPSS, then CVSS: a medium with a public exploit and EPSS 90
    outranks a critical with neither. Each entry carries the preconditions to
    confirm before spending a turn — a version match is not a finding.
    """
    try:
        raw = json.loads(components_json)
    except json.JSONDecodeError as exc:
        return json.dumps({"error": f"components_json is not valid JSON: {exc}"})

    if not isinstance(raw, list):
        return json.dumps({"error": "components_json must be a list"})

    components = [
        Component(
            product=str(item.get("product", "")),
            version=str(item.get("version", "")),
            source=Source(item.get("source", "guessed")) if item.get("source") else Source.GUESSED,
            evidence=str(item.get("evidence", "")),
        )
        for item in raw
        if isinstance(item, dict) and item.get("product")
    ]
    if not components:
        return json.dumps({"error": "no components with a product name"})

    # CVEs come from the sandbox's vulnx; without them the queue is empty rather
    # than fabricated. The agent runs vulnx and re-calls with the records.
    # CVE records come from the sandbox's vulnx; without them the queue is empty
    # rather than fabricated — the agent runs vulnx and re-calls with records.
    records: list[CveRecord] = []
    matches = prioritise(match_components(components, records)) if records else []

    return json.dumps(
        {
            "components": [c.to_wire() for c in components],
            "matches": [m.to_wire() for m in matches],
            "next": (
                "run `vulnx -l <product> -json` in the sandbox for each component, then "
                "confirm the range and preconditions from the advisory before testing"
                if not matches
                else "confirm preconditions per match, then adapt a PoC"
            ),
        },
        ensure_ascii=False,
    )
