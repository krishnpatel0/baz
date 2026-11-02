"""Chain composer — two findings are sometimes one exploit.

A confirmed SSRF and a confirmed IDOR are two medium findings. An SSRF that reads
cloud metadata naming an IAM role, chained into an IDOR that uses it, is one
critical. The composer exists because individual agents cannot see both: each
holds its own findings, compaction erodes them, and nothing asks "do these
combine?".

Findings are reduced to typed primitives, the graph is queried for known
combinations, and each candidate chain must execute end-to-end before it is
reported. Two findings that *could* combine are two findings; only an executed
sequence is a chain.

## The primitive model, and its honest limits

Typing is deliberately narrow. `exec(host)`, `read(host, path)`, `write(host,
path)`, `ssrf(target)`, `identity(role)`, `secret(kind)` cover the mechanical
chains — roughly half of what appears in real reports.

What does not reduce cleanly: `business_logic_price_manipulation` + `race`
becomes a financial loss without fitting any primitive. Those stay untyped, and
the composer's prose pass (below) can still propose them. Forcing everything
through the type system produces graph queries that look rigorous and mean
nothing.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


logger = logging.getLogger(__name__)


class Primitive(StrEnum):
    EXEC = "exec"
    READ = "read"
    WRITE = "write"
    SSRF = "ssrf"
    IDENTITY = "identity"
    SECRET = "secret"  # noqa: S105 - a primitive name, not a credential
    REFLECT = "reflect"


# Patterns that are worth checking, expressed as ordered primitive sequences.
# `*` matches any primitive. These are the combinations that recur in real
# disclosures; novel chains are found by the prose pass, not by this table.
KNOWN_CHAINS: tuple[tuple[Primitive, ...], ...] = (
    (Primitive.SECRET, Primitive.IDENTITY),  # credential -> impersonate
    (Primitive.SECRET, Primitive.WRITE),  # key -> deploy/modify
    (Primitive.SSRF, Primitive.SECRET),  # metadata -> credential
    (Primitive.SSRF, Primitive.IDENTITY),  # metadata -> role name
    (Primitive.READ, Primitive.SECRET),  # file read -> config secrets
    (Primitive.READ, Primitive.IDENTITY),  # file read -> session tokens
    (Primitive.REFLECT, Primitive.IDENTITY),  # xss/csrf -> session theft
    (Primitive.WRITE, Primitive.EXEC),  # upload -> webshell
    (Primitive.EXEC, Primitive.SECRET),  # shell -> config dump
    (Primitive.EXEC, Primitive.READ),  # shell -> file read
)


@dataclass(frozen=True, slots=True)
class Finding:
    """A confirmed finding reduced to what it enables."""

    report_id: str
    title: str
    primitive: Primitive
    target: str
    detail: str = ""
    """What the primitive gives access to — the path, role name, credential kind."""

    def to_wire(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "title": self.title,
            "primitive": str(self.primitive),
            "target": self.target,
            "detail": self.detail,
        }


@dataclass(slots=True)
class ChainCandidate:
    """An ordered combination worth attempting."""

    steps: tuple[Finding, ...]
    pattern: str
    """Human description of the combination."""

    hypothesis: str
    """What the chain would achieve if it executes."""

    proven: bool = False
    evidence: list[str] = field(default_factory=list)

    @property
    def executable(self) -> bool:
        return all(step.primitive for step in self.steps)

    def to_wire(self) -> dict[str, Any]:
        return {
            "pattern": self.pattern,
            "hypothesis": self.hypothesis,
            "steps": [s.to_wire() for s in self.steps],
            "proven": self.proven,
            "evidence": list(self.evidence),
            "report_ids": [s.report_id for s in self.steps],
        }


_CHAIN_DESCRIPTIONS: dict[tuple[Primitive, ...], str] = {
    (Primitive.SECRET, Primitive.IDENTITY): "credential enables impersonation",
    (Primitive.SECRET, Primitive.WRITE): "credential enables modification",
    (Primitive.SSRF, Primitive.SECRET): "SSRF reaches cloud metadata and reads credentials",
    (Primitive.SSRF, Primitive.IDENTITY): "SSRF reveals an identity/role usable elsewhere",
    (Primitive.READ, Primitive.SECRET): "file read exposes secrets",
    (Primitive.READ, Primitive.IDENTITY): "file read exposes session tokens",
    (Primitive.REFLECT, Primitive.IDENTITY): "injection steals a session",
    (Primitive.WRITE, Primitive.EXEC): "writable location reaches execution",
    (Primitive.EXEC, Primitive.SECRET): "execution reads credentials",
    (Primitive.EXEC, Primitive.READ): "execution enables file reads",
}


def reduce_finding(report: dict[str, Any]) -> Finding | None:
    """Type a confirmed finding as a primitive, or None if it does not reduce.

    Classification is keyword-based over the finding's own text, which is
    intentionally conservative: a wrong primitive poisons the graph, and a
    finding that stays untyped simply never participates in chains.
    """
    text = " ".join(
        str(report.get(key) or "")
        for key in ("title", "description", "impact", "technical_analysis")
    ).lower()

    def has(*words: str) -> bool:
        return any(w in text for w in words)

    if has("remote code execution", "rce", "command execution", "webshell", "web shell"):
        primitive = Primitive.EXEC
    elif has("ssrf", "server-side request forgery", "metadata endpoint", "169.254.169.254"):
        primitive = Primitive.SSRF
    elif has("file upload", "arbitrary file write", "wrote to", "file write"):
        primitive = Primitive.WRITE
    elif has("path traversal", "lfi", "local file inclusion", "file read", "arbitrary file read"):
        primitive = Primitive.READ
    elif has("credential", "api key", "password hash", "private key", "token disclosure"):
        primitive = Primitive.SECRET
    elif has("account takeover", "authentication bypass", "session hijack", "impersonat"):
        primitive = Primitive.IDENTITY
    elif has("xss", "cross-site scripting", "html injection", "csrf"):
        primitive = Primitive.REFLECT
    else:
        return None

    return Finding(
        report_id=str(report.get("id") or "?"),
        title=str(report.get("title") or "untitled"),
        primitive=primitive,
        target=str(report.get("target") or report.get("endpoint") or "?"),
        detail=str(report.get("impact") or "")[:200],
    )


def compose(findings: list[Finding]) -> list[ChainCandidate]:
    """Query the typed findings for known combinations.

    Same-target pairs are preferred but not required — a credential found in a
    public repo and an admin panel on the target are a valid chain across
    sources. Order matters: the pattern table is directional.
    """
    candidates: list[ChainCandidate] = []
    used: set[tuple[str, ...]] = set()

    for pattern in KNOWN_CHAINS:
        for first in findings:
            if first.primitive is not pattern[0]:
                continue
            for second in findings:
                if second is first or second.primitive is not pattern[1]:
                    continue
                key = tuple(sorted((first.report_id, second.report_id)))
                if key in used:
                    continue
                used.add(key)
                candidates.append(
                    ChainCandidate(
                        steps=(first, second),
                        pattern=_CHAIN_DESCRIPTIONS.get(
                            pattern, " -> ".join(p.value for p in pattern)
                        ),
                        hypothesis=_hypothesis(first, second),
                    )
                )
    return candidates


def _hypothesis(first: Finding, second: Finding) -> str:
    """What the chain would achieve, in one sentence a triager can evaluate."""
    return (
        f"Combining '{first.title}' ({first.primitive.value}) with "
        f"'{second.title}' ({second.primitive.value})"
        + (f" on {second.target}" if second.target and second.target != "?" else "")
        + f": {first.detail or first.primitive.value} enables {second.primitive.value}."
    )


def prose_candidates(findings: list[Finding]) -> list[dict[str, Any]]:
    """Un-typed findings that a model pass should consider for chains.

    Business-logic bugs, race conditions and multi-step flows do not reduce to
    primitives but do chain. This returns them with enough context for a model
    pass to reason over, instead of forcing them through a type system that
    would mangle them.
    """
    return [
        {
            "report_id": str(r.get("id") or "?"),
            "title": str(r.get("title") or ""),
            "impact": str(r.get("impact") or "")[:300],
            "note": "does not reduce to a primitive; consider in the model pass",
        }
        for r in findings
        if reduce_finding(r) is None
    ]


def full_compose(reports: list[dict[str, Any]]) -> dict[str, Any]:
    """Compose over raw report dicts: typed candidates plus the prose queue."""
    typed: list[Finding] = []
    untyped_ids: set[str] = set()
    for report in reports:
        finding = reduce_finding(report)
        if finding is not None:
            typed.append(finding)
        else:
            untyped_ids.add(str(report.get("id") or "?"))

    candidates = compose(typed)
    prose = [p for p in prose_candidates(reports) if p["report_id"] in untyped_ids]
    return {
        "candidates": [c.to_wire() for c in candidates],
        "prose_queue": prose,
        "typed_count": len(typed),
        "candidate_count": len(candidates),
    }
