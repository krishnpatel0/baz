"""Evidence bundles — a finding as one flat folder a triager can open.

The gap this closes: a report today is text fields with an `evidence` string.
The screenshots that prove it were taken, looked at by the model, and thrown
away. Nothing ties an artifact to a finding, so a hunter who wants to submit has
to reproduce the whole thing by hand.

A bundle keeps a finding self-contained: one folder per finding, flat, with the
report inside it and no subdirectories to dig through.

```
<run>/vulnerabilities/vuln-0001/
  vuln-0001.md          the report, citing every artifact below by name
  finding.json          canonical record
  01-initial-state.png  01-login-as-bob.png   ... captioned screenshots
  01-request.http       01-response.http      ... raw exchanges
  01-exploit.py         02-payload.txt        ... the exact payloads
  01-sample-records.json                       ... impact proof
  console.log  errors.log  capture.har         ... when the bug needs them
  timeline.md           ordered, timestamped narration
```

Flat on purpose. Nesting the same seven artifact kinds into seven subdirectories
makes the common case — open the finding, look at the picture, read the payload —
three clicks instead of none, and a zipped finding indistinguishable from a
source tree. The artifact kind is in the filename.

Screenshots are captioned at capture time by this module rather than by the
model. A model-written caption can describe something the image does not show;
a caption burned in when the shutter fires cannot.
"""

from __future__ import annotations

import base64
import binascii
import io
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from PIL import Image, ImageDraw

from baz.evidence.artifacts import PayloadArtifact, PayloadStore, capture_impact, classify_language


if TYPE_CHECKING:
    from pathlib import Path


logger = logging.getLogger(__name__)


# Findings live under the same ``vulnerabilities/`` directory as their reports, so
# a finding and its report are one folder rather than two trees joined by a name.
VULNERABILITIES_DIRNAME = "vulnerabilities"
CAPTION_HEIGHT = 34
CAPTION_MAX_CHARS = 96
"""Bound on a caption line. Long enough to say what happened, short enough to
read at a glance in a report; anything longer gets truncated in the image and
kept in full in ``timeline.md``."""

_SLUG_RE = re.compile(r"[^a-z0-9]+")
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

_NUMBERED_ARTIFACT = re.compile(r"^\d{2}-")
"""A bundle artifact always carries its step as a leading ``NN-`` prefix, which
is what lets the flat folder be read back without a per-kind subdirectory to
scan. The report and the record are named explicitly and never match."""

_PAYLOAD_SUFFIXES = frozenset(
    {".py", ".sh", ".txt", ".http", ".json", ".js", ".php", ".xml", ".yml", ".yaml", ".rb", ".pl"}
)


def _slug(value: str, *, limit: int = 60) -> str:
    cleaned = _SLUG_RE.sub("-", value.lower()).strip("-")
    return (cleaned or "finding")[:limit]


@dataclass(slots=True)
class Capture:
    """One artifact plus the words that explain it."""

    path: str
    """Bundle-relative path of the file."""

    kind: str
    """One of ``screenshot``, ``payload``, ``impact``, ``http``, ``console``,
    ``har``, ``file`` or ``note``."""

    label: str
    step: int

    def to_wire(self) -> dict[str, Any]:
        return {"path": self.path, "kind": self.kind, "label": self.label, "step": self.step}


@dataclass(slots=True)
class EvidenceBundle:
    """A finding's on-disk evidence: one flat folder, report included."""

    root: Path
    finding_id: str
    title: str
    captures: list[Capture] = field(default_factory=list)
    events: list[tuple[str, str]] = field(default_factory=list)
    """``(timestamp, line)`` pairs, rendered into ``timeline.md`` at seal time."""

    @property
    def report_path(self) -> Path:
        """The finding's Markdown report — inside the bundle, beside its evidence."""
        return self.root / f"{self.finding_id}.md"

    def payloads(self) -> PayloadStore:
        """The payload store for this finding, rooted at the bundle (flat)."""
        return PayloadStore(self.root)

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

    def record(self, message: str) -> None:
        """Append a timeline event. Cheap; call it liberally."""
        self.events.append((datetime.now(UTC).strftime("%H:%M:%S"), message))

    def record_payload(
        self,
        content: str,
        *,
        label: str,
        step: int | None = None,
        language: str | None = None,
        produced: str = "",
    ) -> str:
        """Save the exact payload used and return its bundle-relative path.

        Flat, in the bundle folder itself: the report cites ``02-exploit.py`` and
        that file sits next to it, not one directory down. The extension matches
        the language — a Python exploit stays a `.py`, a raw request becomes
        `.http` — because a triager reading a 2,000-character SQLi payload
        should not also have to guess whether it is a shell command.
        """
        store = PayloadStore(self.root)
        # Reconcile with anything already written by an earlier call.
        store.artifacts = _existing_payloads(store)
        artifact = store.add(content, label=label, step=step, language=language, produced=produced)
        if artifact is None:
            return ""
        store.write_manifest()
        self.register(
            self.root / artifact.filename,
            kind="payload",
            label=label,
            step=artifact.step or 1,
        )
        return artifact.filename

    def record_impact(
        self,
        records: list[Any],
        *,
        label: str = "sample-records",
        total_seen: int | None = None,
    ) -> str:
        """Save proof data returned by the exploit; return its bundle-relative path."""
        step = self.next_step("impact")
        filename = f"{step:02d}-{_slug(label)}.json"
        evidence = capture_impact(
            self.root,
            records,
            label=label,
            total_seen=total_seen,
            filename=filename,
        )
        if evidence is None:
            return ""
        self.record(f"impact sample saved: {evidence.note}")
        self.register(self.root / evidence.note, kind="impact", label=label, step=step)
        return evidence.note

    def capture_screenshot(
        self,
        data: bytes,
        *,
        label: str,
        url: str = "",
    ) -> str:
        """Store one captioned screenshot; return its bundle-relative filename.

        ``data`` is the PNG the browser produced, which is what makes capturing
        possible at all: the sandbox runs the browser, the host writes the
        bundle, and a screenshot that is only ever written to a container path
        never reaches the hunter. The caption is burned in here, at the moment
        of capture, so it cannot drift from what the pixels show.
        """
        step = self.next_step("screenshot")
        filename = f"{step:02d}-{_slug(label)}.png"
        target = self.root / filename
        text = " ".join(str(label).split())[:CAPTION_MAX_CHARS]
        if not _caption_png_bytes(data, target, label=text, step=step, url=url):
            # Captioning must never lose the evidence: store the raw frame.
            target.write_bytes(data)
        self.register(target, kind="screenshot", label=label, step=step)
        return filename

    def record_text(
        self,
        text: str,
        *,
        filename: str,
        kind: str,
        label: str = "",
    ) -> str:
        """Store a text artifact (console log, HTTP exchange, HAR) flat."""
        step = self.next_step(kind)
        name = filename if filename.startswith(f"{step:02d}-") else f"{step:02d}-{filename}"
        target = self.root / name
        _write_text(target, text if text.endswith("\n") else text + "\n")
        self.register(target, kind=kind, label=label or name, step=step)
        return name

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
            for kind in ("screenshot", "payload", "impact", "http", "console", "har", "note"):
                items = sorted(self.of_kind(kind), key=lambda c: c.step)
                if not items:
                    continue
                lines.append(f"**{kind}**")
                lines.extend(f"- `{c.path}` — {c.label}" for c in items)
                lines.append("")
        return "\n".join(lines).rstrip() + "\n"


def _existing_payloads(store: Any) -> list[Any]:
    """Reload payload artifacts already on disk so steps do not restart at 1."""

    if not store.root.is_dir():
        return []
    found: list[Any] = []
    for index, path in enumerate(sorted(store.root.iterdir()), start=1):
        # The bundle is flat, so a payload is any numbered artifact that is not a
        # file this module writes itself — the report, the record, the timeline,
        # captioned screenshots — or a text artifact of another kind.
        if not path.is_file() or not _NUMBERED_ARTIFACT.match(path.name):
            continue
        if path.suffix in {".json", ".md", ".png"}:
            continue
        try:
            body = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if classify_language(body) == "text" and path.suffix not in _PAYLOAD_SUFFIXES:
            continue
        found.append(
            PayloadArtifact(
                filename=path.name,
                language=classify_language(body),
                content=body,
                label=path.stem,
                step=index,
            )
        )
    return found


def open_bundle(run_dir: Path, finding_id: str, title: str) -> EvidenceBundle:
    """Create the flat on-disk folder for a new finding, report included."""
    root = run_dir / VULNERABILITIES_DIRNAME / finding_id
    root.mkdir(parents=True, exist_ok=True)
    bundle = EvidenceBundle(root=root, finding_id=finding_id, title=title)
    bundle.record(f"bundle opened for {title}")
    return bundle


def _caption_png_bytes(
    data: bytes,
    destination: Path,
    *,
    label: str,
    step: int,
    url: str = "",
) -> bool:
    """Burn a caption bar onto PNG ``data`` and write it to ``destination``.

    Returns False (leaving ``destination`` unwritten) when the bytes are not a
    readable image, so the caller can fall back to storing the raw frame rather
    than losing the screenshot.
    """
    if not data or not data.startswith(_PNG_MAGIC):
        return False

    try:
        with Image.open(io.BytesIO(data)) as raw:
            image = raw.convert("RGB")
        width, height = image.size
        canvas = Image.new("RGB", (width, height + CAPTION_HEIGHT), (17, 20, 24))
        canvas.paste(image, (0, 0))
        draw = ImageDraw.Draw(canvas)
        bar_top = height + 6
        draw.text((10, bar_top), f"Step {step}  ·  {label}", fill=(235, 238, 242))
        if url:
            draw.text((10, bar_top + 15), url[:140], fill=(150, 158, 168))
        destination.parent.mkdir(parents=True, exist_ok=True)
        canvas.save(destination, "PNG", optimize=True)
    except (OSError, ValueError):
        logger.exception("could not caption screenshot for step %d", step)
        return False
    return True


def _write_text(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(body, encoding="utf-8")
    tmp.replace(path)


def _write_json(path: Path, payload: Any) -> None:
    _write_text(path, json.dumps(payload, indent=2, ensure_ascii=False, default=str) + "\n")


async def read_png_from_sandbox(session: Any, container_path: str) -> bytes | None:
    """Read a screenshot the sandbox wrote, so it can be captioned host-side.

    The browser runs inside the container and writes its screenshots there; only
    a read like this brings the pixels out. Returns ``None`` — never raising —
    when the file is missing or unreadable, because a lost screenshot must not
    abort filing the finding it belongs to.

    ``BaseSandboxSession.read`` is a coroutine returning a binary handle, so this
    is awaited rather than opened synchronously.
    """
    if session is None:
        return None
    try:
        handle = await session.read(container_path)
        data = handle.read()
    except Exception:  # noqa: BLE001 - an unreadable screenshot is not fatal
        logger.debug("screenshot not readable at %s", container_path, exc_info=True)
        return None
    if isinstance(data, str):
        try:
            return base64.b64decode(data, validate=True)
        except (binascii.Error, ValueError):
            return None
    return bytes(data) if data else None
