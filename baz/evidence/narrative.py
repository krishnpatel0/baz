"""The triager-facing narrative — a walkthrough a stranger can follow.

Triagers reject reports for one dominant reason: they cannot reproduce it in a
few minutes. The fix is not more prose, it is a strict 1:1 mapping between what
the report says happened, the file that did it, and the picture that proves it.

```
Step 2 — the payload fired
  → payload/02-exploit.py     (the exact script)
  → screenshots/02-alert.png  (captioned at capture time)
  → observed: alert(document.domain) executed with the session cookie in scope
```

Every step is a row in that table. A step without an artifact is a step the
triager has to take on faith, so this module marks it as unproven rather than
padding the narrative.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


@dataclass(slots=True)
class Step:
    """One numbered action in the reproduction."""

    number: int
    action: str
    """What was done, in the imperative — "Send the payload in the search field"."""

    observed: str = ""
    """What came back that proved it — the line a triager checks."""

    payload_file: str = ""
    """Bundle-relative path to the exact artifact used."""

    screenshot: str = ""
    """Bundle-relative path to the captioned image."""

    @property
    def proven(self) -> bool:
        return bool(self.payload_file or self.screenshot or self.observed)

    def to_wire(self) -> dict[str, Any]:
        return {
            "step": self.number,
            "action": self.action,
            "observed": self.observed,
            "payload_file": self.payload_file,
            "screenshot": self.screenshot,
            "proven": self.proven,
        }


@dataclass(slots=True)
class Narrative:
    steps: list[Step] = field(default_factory=list)

    def add(
        self,
        action: str,
        *,
        observed: str = "",
        payload_file: str = "",
        screenshot: str = "",
    ) -> Step:
        step = Step(
            number=len(self.steps) + 1,
            action=action.strip(),
            observed=observed.strip(),
            payload_file=payload_file,
            screenshot=screenshot,
        )
        self.steps.append(step)
        return step

    @property
    def unproven(self) -> list[Step]:
        return [step for step in self.steps if not step.proven]

    def render(self) -> str:
        """Markdown walkthrough with artifacts interleaved in order.

        Images sit directly under the step that produced them rather than in a
        gallery at the end, because the reader is walking down the page matching
        each picture to the sentence above it.
        """
        if not self.steps:
            return ""
        lines = ["## Reproduction Walkthrough", ""]
        for step in self.steps:
            lines.append(f"### Step {step.number} — {step.action}")
            lines.append("")
            if step.payload_file:
                lines.append(f"Payload: [`{step.payload_file}`]({step.payload_file})")
                lines.append("")
            if step.observed:
                lines.append("```")
                lines.append(step.observed)
                lines.append("```")
                lines.append("")
            if step.screenshot:
                lines.append(f"![Step {step.number}]({step.screenshot})")
                lines.append("")
            if not step.proven:
                lines.append("_This step has no attached artifact._")
                lines.append("")
        if self.unproven:
            lines.append(
                f"> {len(self.unproven)} of {len(self.steps)} steps carry no artifact. "
                "A triager will have to take those on trust."
            )
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    def to_wire(self) -> list[dict[str, Any]]:
        return [step.to_wire() for step in self.steps]


def build_from_reports(report: dict[str, Any], bundle_root: Any = None) -> Narrative:
    """Reconstruct a walkthrough from what a finding already recorded.

    Used when the agent did not supply an explicit narrative. It is a real
    reconstruction, not a summary: the steps come from ``poc_description`` when
    it is step-shaped, and the artifacts are attached from the bundle in the
    order they were captured. Steps that cannot be matched to a file stay
    unproven, which is the honest outcome.
    """
    narrative = Narrative()

    description = str(report.get("poc_description") or "").strip()
    raw_steps = _split_steps(description)

    screenshots: list[str] = []
    payloads: list[str] = []
    root = Path(bundle_root) if bundle_root is not None else None
    if root is not None and root.is_dir():
        if (root / "screenshots").is_dir():
            screenshots = [
                f"../findings/{root.name}/screenshots/{p.name}"
                for p in sorted((root / "screenshots").glob("*.png"))
            ]
        payload_dir = root / "payload"
        if payload_dir.is_dir():
            payloads = [
                f"../findings/{root.name}/payload/{p.name}"
                for p in sorted(payload_dir.iterdir())
                if p.is_file() and p.name != "manifest.json"
            ]

    for index, text in enumerate(raw_steps):
        narrative.add(
            text,
            payload_file=payloads[index] if index < len(payloads) else "",
            screenshot=screenshots[index] if index < len(screenshots) else "",
        )

    if not narrative.steps and payloads:
        narrative.add(
            "Run the attached payload against the target",
            payload_file=payloads[0],
            screenshot=screenshots[0] if screenshots else "",
        )
    return narrative


def _split_steps(description: str) -> list[str]:
    """Pull numbered or bulleted steps out of a free-form description.

    Anything else is returned as a single step, because inventing structure
    where the agent wrote prose would misrepresent it.
    """
    if not description:
        return []
    numbered = re.findall(r"(?m)^\s*(?:\d+[.)]|[-*])\s+(.+)$", description)
    if len(numbered) >= 2:
        return [step.strip() for step in numbered]
    lines = [line.strip() for line in description.splitlines() if line.strip()]
    return lines if len(lines) > 1 else [description]
