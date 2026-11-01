"""Data model for the payload arsenal.

A payload is only useful to an agent if the agent can answer three questions
about it without guessing: *where does this go*, *what does success look like*,
and *what variant survives this obstacle*. The fields here exist to answer
those three questions mechanically, so the model does selection and judgment
rather than recall.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


CANARY = "{{CANARY}}"
"""Placeholder replaced per-sweep with a unique token.

Every payload carries it wherever it should appear in the response if the
injection succeeded. A sweep substitutes one fresh token per run, so a
reflection is a substring match rather than a model judgment call over
hundreds of responses.
"""


class Signal(StrEnum):
    """How a successful injection is observed.

    The harness uses this to pick its detection strategy; the model uses it to
    know what evidence a validator will demand.
    """

    REFLECTION = "reflection"
    """The canary appears in the response — XSS, SSTI, HTML injection, CRLF."""

    EXECUTION = "execution"
    """The canary ran — DOM XSS, confirmed through a headless browser."""

    ERROR = "error"
    """A dialect- or engine-specific error string appears — SQLi, SSTI, XXE."""

    TIMING = "timing"
    """Response latency diverges from a control by a stable margin — blind SQLi,
    blind command injection, blind SSTI."""

    OOB = "oob"
    """The target called back to a listener we control — SSRF, XXE, blind RCE."""

    DIFFERENTIAL = "differential"
    """Response differs from a matched control in status, length, or structure."""

    STATE = "state"
    """Server-side state changed in a way the app reports back — race, logic,
    auth bypass, open redirect (final host differs)."""


@dataclass(frozen=True, slots=True)
class Payload:
    """One injectable string plus everything needed to evaluate it."""

    id: str
    payload: str
    vuln_class: str
    context: str
    signal: Signal

    dialect: str | None = None
    """DBMS / template engine / language this is specific to, if any."""

    requires: tuple[str, ...] = ()
    """Preconditions the tester must have already established, e.g.
    ``("html_injection",)`` or ``("stacked_queries",)``."""

    detect: str | None = None
    """Explicit needle for :attr:`Signal.ERROR` / :attr:`Signal.REFLECTION`.

    Defaults to the canary when unset, which is right for reflection-style
    payloads. Error- and timing-based payloads set it to the string that proves
    the injection actually reached the engine."""

    waf: tuple[str, ...] = ()
    """WAF families this variant is known to survive. Empty means untested —
    still useful, just not a bypass claim."""

    weight: float = 1.0
    """Ordering hint within an equally-matched set. Higher sorts first."""

    notes: str = ""
    ref: str = ""

    def __post_init__(self) -> None:
        if self.detect is None and self.signal in (Signal.REFLECTION, Signal.EXECUTION):
            object.__setattr__(self, "detect", CANARY)

    @property
    def needle(self) -> str:
        """The substring a sweep greps for; the canary unless overridden."""
        return self.detect if self.detect is not None else CANARY

    def materialize(self, canary: str) -> str:
        """Render the payload with a concrete canary token."""
        return self.payload.replace(CANARY, canary)

    def to_wire(self) -> dict[str, Any]:
        """Compact dict for tool output — empty fields are dropped."""
        out: dict[str, Any] = {
            "id": self.id,
            "payload": self.payload,
            "signal": str(self.signal),
        }
        if self.dialect:
            out["dialect"] = self.dialect
        if self.requires:
            out["requires"] = list(self.requires)
        if self.detect and self.detect != CANARY:
            out["detect"] = self.detect
        if self.waf:
            out["waf"] = list(self.waf)
        if self.notes:
            out["notes"] = self.notes
        return out


@dataclass(frozen=True, slots=True)
class Variant:
    """A payload after an encoding ladder has been applied."""

    payload: Payload
    encoding: str
    rendered: str


@dataclass(slots=True)
class Selection:
    """Result of a selector query, with the reasoning made visible."""

    payloads: list[Payload] = field(default_factory=list)
    vuln_class: str = ""
    context: str | None = None
    dialect: str | None = None
    waf: str | None = None
    total_matched: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def matched(self) -> int:
        return self.total_matched

    def summary(self) -> str:
        bits = [f"{len(self.payloads)} of {self.total_matched} payloads"]
        bits.append(f"class={self.vuln_class}")
        if self.context:
            bits.append(f"context={self.context}")
        if self.dialect:
            bits.append(f"dialect={self.dialect}")
        if self.waf:
            bits.append(f"waf={self.waf}")
        return " · ".join(bits)
