"""Live browser viewport for the run viewer.

The agent drives a headless Chromium inside the sandbox. That makes the agent's
work invisible: you see tool calls scroll past, not the page it is looking at,
and you cannot tell a slow page from a stuck agent.

This exposes the current viewport as a JPEG the viewer polls. Deliberately the
*polling* design rather than a WebSocket relay: the viewer is a plain
`BaseHTTPRequestHandler` with no socket plumbing, and at 1-2 frames per second a
frame-on-request is indistinguishable from a stream while adding no new transport,
no new failure mode, and no new thing to secure.

`agent-browser` 0.4x can stream frames over a WebSocket, and that is the richer
answer — interactive input, 30fps, no polling. It is also the answer that needs
its own listener, its own auth, and its own supervisor. This module is the 20%
that delivers most of the value; the relay can replace it later behind the same
endpoint.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


FRAME_DIR = "/workspace/.live-view"
FRAME_LIMIT = 2
"""Frames kept in the sandbox. Two lets a newer frame be written while an older
one is being fetched, without letting a slow poller grow a directory."""

MIN_INTERVAL_S = 0.5
"""Floor between captures. One throttle point, shared by however many viewers
poll — otherwise five open tabs are five screenshots a second against the
agent's browser."""


@dataclass(slots=True)
class Frame:
    data: bytes
    captured_at: float
    page_id: int | None = None

    @property
    def age_ms(self) -> int:
        return int((time.time() - self.captured_at) * 1000)


class FrameGrabber:
    """Captures the sandbox browser viewport on demand, throttled.

    One grabber per scan. It holds the sandbox session and the CDP page id, and
    it never blocks its caller for longer than one capture.
    """

    def __init__(self, session: Any, *, page_id: int | None = None) -> None:
        self._session = session
        self._page_id = page_id
        self._lock = asyncio.Lock()
        self._last_at = 0.0
        self._last_frame: Frame | None = None

    async def grab(self) -> Frame | None:
        """Return the current viewport, or the last frame if we are throttled.

        Never raises: the viewer is decoration. A dead browser or a failed
        screenshot returns ``None`` and the UI shows nothing, which is the
        correct outcome — it must not take the run down with it.
        """
        async with self._lock:
            now = time.time()
            if self._last_frame is not None and now - self._last_at < MIN_INTERVAL_S:
                return self._last_frame

            try:
                data = await self._capture()
            except (OSError, RuntimeError, ValueError):
                logger.debug("live viewport capture failed", exc_info=True)
                return self._last_frame

            if data is None:
                return self._last_frame

            self._last_at = now
            self._last_frame = Frame(data=data, captured_at=now, page_id=self._page_id)
            return self._last_frame

    async def _capture(self) -> bytes | None:
        """Ask the sandbox browser for one screenshot and read it back."""
        # The CLI decides the extension from --format and ignores the one on
        # --filePath, so the path has to agree with the format or the file lands
        # somewhere we are not reading.
        path = f"{FRAME_DIR}/{int(time.time() * 1000)}.jpeg"
        page = self._page_id if self._page_id is not None else 1
        # chrome-devtools takes the picture; the CLI is already in the image and
        # needs no MCP round trip for a single frame.
        command = (
            f"mkdir -p {FRAME_DIR} && "
            f"/home/pentester/.npm-global/bin/chrome-devtools take_screenshot {page} "
            f"--filePath {path} --format jpeg --quality 60 >/dev/null 2>&1"
        )
        await self._session.exec(command)
        await self._session.exec(
            f"ls -1t {FRAME_DIR}/*.jpeg {FRAME_DIR}/*.jpg 2>/dev/null "
            f"| tail -n +{FRAME_LIMIT + 1} | xargs -r rm -f"
        )
        try:
            raw = await self._session.read(Path(path))
        except (OSError, ValueError):
            return None
        if isinstance(raw, (bytes, bytearray)):
            return bytes(raw)
        # The SDK returns a stream-like object in some backends.
        reader = getattr(raw, "read", None)
        if callable(reader):
            chunk = reader()
            if asyncio.iscoroutine(chunk):
                chunk = await chunk
            return bytes(chunk) if chunk else None
        return None


_GRABBERS: dict[str, FrameGrabber] = {}
"""Live grabbers by scan id.

The runner owns the sandbox session; the viewer is launched from the TUI, which
never sees one. This is the seam: the runner registers here when its sandbox is
up, the viewer asks here when it needs a frame. Keyed by scan so two concurrent
scans do not show each other's browsers.
"""


def register(scan_id: str, grabber: FrameGrabber) -> None:
    _GRABBERS[scan_id] = grabber


def lookup(scan_id: str | None = None) -> FrameGrabber | None:
    """The grabber for ``scan_id``, or the only one if a scan id is not given."""
    if scan_id:
        return _GRABBERS.get(scan_id)
    if len(_GRABBERS) == 1:
        return next(iter(_GRABBERS.values()))
    return None


def unregister(scan_id: str) -> None:
    _GRABBERS.pop(scan_id, None)


def encode_frame(frame: Frame) -> dict[str, Any]:
    """JSON-safe frame envelope for the viewer.

    Base64 rather than a binary response so the existing JSON API can carry it —
    one endpoint shape, no content negotiation.
    """
    return {
        "image": base64.b64encode(frame.data).decode("ascii"),
        "mime": "image/jpeg",
        "age_ms": frame.age_ms,
        "page_id": frame.page_id,
    }


def available(binary: str = "/home/pentester/.npm-global/bin/chrome-devtools") -> bool:
    """Whether the sandbox has the tool the grabber needs."""
    return shutil.which(binary) is not None
