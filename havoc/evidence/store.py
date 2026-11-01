"""Evidence bundles — a finding as a directory a triager can open.

The gap this closes: a report today is text fields with an `evidence` string.
The screenshots that prove it were taken, looked at by the model, and thrown
away. Nothing ties an artifact to a finding, so a hunter who wants to submit has
to reproduce the whole thing by hand.

A bundle makes the finding self-contained:

```
<run>/findings/F-0041/
  finding.json          canonical record
  screenshots/          01-initial-state.png, 02-payload-sent.png, ...
  http/                 001-request.http, 001-response.http
  console/              console.log, errors.log
  har/                  capture.har
  notes/                free-form artifacts the agent attached
  timeline.md           ordered, timestamped narration
```

Screenshots are captioned at capture time by this module rather than by the
model. A model-written caption can describe something the image does not show;
a caption burned in when the shutter fires cannot.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from PIL import Image, ImageDraw


if TYPE_CHECKING:
    from pathlib import Path


logger = logging.getLogger(__name__)


FINDINGS_DIRNAME = "findings"
CAPTION_HEIGHT = 34
CAPTION_MAX_CHARS = 96
"""Bound on a caption line. Long enough to say what happened, short enough to
read at a glance in a report; anything longer gets truncated in the image and
kept in full in ``timeline.md``."""

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slug(value: str, *, limit: int = 60) -> str:
    cleaned = _SLUG_RE.sub("-", value.lower()).strip("-")
    return (cleaned or "finding")[:limit]


@dataclass(slots=True)
class Capture:
    """One artifact plus the words that explain it."""

    path: str
    """Bundle-relative path of the file."""

    kind: str
    """``screenshot`` | ``http`` | ``console`` | ``har`` | ``note``."""

    label: str
    step: int

    def to_wire(self) -> dict[str, Any]:
        return {"path": self.path, "kind": self.kind, "label": self.label, "step": self.step}


@dataclass(slots=True)
class EvidenceBundle:
    """A finding's on-disk evidence collection."""

    root: Path
    finding_id: str
    title: str
    captures: list[Capture] = field(default_factory=list)
    events: list[tuple[str, str]] = field(default_factory=list)
    """``(timestamp, line)`` pairs, rendered into ``timeline.md`` at seal time."""

    @property
    def screenshots_dir(self) -> Path:
        return self.root / "screenshots"

    @property
    def http_dir(self) -> Path:
        return self.root / "http"

    def record(self, message: str) -> None:
        """Append a timeline event. Cheap; call it liberally."""
        self.events.append((datetime.now(UTC).strftime("%H:%M:%S"), message))

    def next_step(self, kind: str) -> int:
        """Ordinal for the next artifact of ``kind``, so files sort by order."""
        return sum(1 for capture in self.captures if capture.kind == kind) + 1

    def register(self, path: Path, *, kind: str, label: str, step: int) -> Capture:
        capture = Capture(
            path=str(path.relative_to(self.root)).replace("\\", "/"),
            kind=kind,
            label=label,
            step=step,
        )
        self.captures.append(capture)
        self.record(f"{kind} {step}: {label}")
        return capture

    def of_kind(self, kind: str) -> list[Capture]:
        return [capture for capture in self.captures if capture.kind == kind]

    def seal(self, record: dict[str, Any]) -> Path:
        """Write ``finding.json`` and ``timeline.md``; return the bundle root.

        Called once, when the finding is filed. Everything before this is
        append-only so a failed reproduction still leaves usable evidence.
        """
        payload = {
            **record,
            "bundle": {
                "finding_id": self.finding_id,
                "title": self.title,
                "sealed_at": datetime.now(UTC).isoformat(),
                "captures": [capture.to_wire() for capture in self.captures],
            },
        }
        _write_json(self.root / "finding.json", payload)
        _write_text(self.root / "timeline.md", self._render_timeline())
        return self.root

    def _render_timeline(self) -> str:
        lines = [f"# {self.title}", "", f"Finding: `{self.finding_id}`", ""]
        for stamp, message in self.events:
            lines.append(f"- `{stamp}` {message}")
        if self.captures:
            lines.extend(["", "## Artifacts", ""])
            for kind in ("screenshot", "http", "console", "har", "note"):
                items = sorted(self.of_kind(kind), key=lambda c: c.step)
                if not items:
                    continue
                lines.append(f"**{kind}**")
                lines.extend(f"- `{c.path}` — {c.label}" for c in items)
                lines.append("")
        return "\n".join(lines).rstrip() + "\n"


def open_bundle(run_dir: Path, finding_id: str, title: str) -> EvidenceBundle:
    """Create the on-disk skeleton for a new finding."""
    root = run_dir / FINDINGS_DIRNAME / finding_id
    for child in ("screenshots", "http", "console", "har", "notes"):
        (root / child).mkdir(parents=True, exist_ok=True)
    bundle = EvidenceBundle(root=root, finding_id=finding_id, title=title)
    bundle.record(f"bundle opened for {title}")
    return bundle


def caption_image(source: Path, destination: Path, *, label: str, step: int, url: str = "") -> bool:
    """Burn a caption bar onto a screenshot.

    Returns False (leaving ``destination`` unwritten) when Pillow is missing or
    the image cannot be read, so a captioning failure never loses the evidence —
    the caller falls back to copying the original.

    Why burn it in rather than keep a sidecar caption: the report embeds the
    image, and an image without its caption beside it is ambiguous the moment it
    is dragged anywhere. The caption has to travel with the pixels.
    """
    text = " ".join(str(label).split())[:CAPTION_MAX_CHARS]
    try:
        with Image.open(source) as raw:
            image = raw.convert("RGB")
        width, height = image.size
        canvas = Image.new("RGB", (width, height + CAPTION_HEIGHT), (17, 20, 24))
        canvas.paste(image, (0, 0))
        draw = ImageDraw.Draw(canvas)
        bar_top = height + 6
        draw.text((10, bar_top), f"Step {step}  ·  {text}", fill=(235, 238, 242))
        if url:
            draw.text((10, bar_top + 15), url[:140], fill=(150, 158, 168))
        canvas.save(destination, "PNG", optimize=True)
    except (OSError, ValueError):
        logger.exception("could not caption %s", source)
        return False
    return True


def _write_text(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(body, encoding="utf-8")
    tmp.replace(path)


def _write_json(path: Path, payload: Any) -> None:
    _write_text(path, json.dumps(payload, indent=2, ensure_ascii=False, default=str) + "\n")


def copy_into(source: Path, target: Path) -> bool:
    """Move an artifact from the sandbox mirror into the bundle."""
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    except OSError:
        logger.exception("could not copy %s into bundle", source)
        return False
    return True
