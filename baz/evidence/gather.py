"""Collect a finding's evidence out of the sandbox, unprompted.

Filing a report gathers the proof by default: the screenshots the browser wrote,
the proxied exchanges the finding cites, and any file the agent names. Without
this the artifacts stay in a container that is about to be destroyed, and the
report renders with no proof of the vulnerability it describes.

Everything here is best-effort. A missing screenshot must never cost the
finding, so each step is guarded and each failure returns a human-readable
warning that rides back in the tool result — a gap the agent can still fix
rather than a silence it cannot see.

Split out of the reporting tool so it can be tested without a scan, and so the
tool module stays about filing rather than about moving files.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from baz.browser.stack import WORKSPACE_ROOT
from baz.evidence.store import read_png_from_sandbox
from baz.tools.proxy import caido_api


logger = logging.getLogger(__name__)

_SCREENSHOT_DIRNAME = ".agent-browser-screenshots"


async def gather_default_evidence(
    bundle: Any,
    *,
    sandbox_session: Any,
    http_exchange_ids: list[str] | None,
) -> list[str]:
    """Collect everything the sandbox still holds for this finding.

    Returns warnings for what could not be collected. An empty list means the
    gathering ran without complaint — not necessarily that every artifact type
    was found.
    """
    warnings: list[str] = []
    if sandbox_session is None:
        return warnings

    if await collect_screenshots(bundle, sandbox_session) == 0:
        warnings.append(
            "No screenshots were found in the sandbox. Take screenshots with the "
            "browser tool and pass their sandbox paths via evidence_files."
        )
    for exchange_id in http_exchange_ids or []:
        if not exchange_id.strip():
            continue
        try:
            await capture_http_exchange(bundle, exchange_id.strip())
        except Exception:
            logger.exception("could not capture HTTP exchange %s", exchange_id)
            warnings.append(f"HTTP exchange {exchange_id} could not be captured.")
    return warnings


async def collect_screenshots(bundle: Any, sandbox_session: Any) -> int:
    """Pull every browser screenshot out of the sandbox and into the bundle.

    Scans the workspace screenshot directory rather than tracking individual
    paths, so a screenshot the agent took without telling anyone is still
    included. Files are captioned host-side, because the container holds the
    browser and the host holds the bundle.
    """
    directory = f"{WORKSPACE_ROOT}/{_SCREENSHOT_DIRNAME}"
    try:
        entries = await sandbox_session.ls(directory)
    except Exception:
        logger.debug("no sandbox screenshot directory at %s", directory, exc_info=True)
        return 0

    paths: list[str] = []
    for entry in entries or []:
        name = getattr(entry, "path", None) or getattr(entry, "name", "")
        if isinstance(name, str) and name.lower().endswith(".png"):
            paths.append(name if name.startswith("/") else f"{directory}/{name}")

    collected = 0
    for path in sorted(paths):
        data = await read_png_from_sandbox(sandbox_session, path)
        if not data:
            continue
        try:
            bundle.capture_screenshot(data, label=screenshot_label(path), url="")
        except (OSError, ValueError):
            logger.exception("could not store screenshot %s", path)
            continue
        collected += 1
    return collected


def screenshot_label(container_path: str) -> str:
    """Human label for a screenshot, from its filename."""
    stem = re.split(r"[\\/]", container_path)[-1].rsplit(".", 1)[0]
    return stem.replace("_", " ").replace("-", " ").strip() or "screenshot"


async def capture_http_exchange(bundle: Any, exchange_id: str) -> None:
    request_result = await caido_api.view_request(exchange_id, part="request")
    raw_request = getattr(getattr(request_result, "request", None), "raw", None)
    if isinstance(raw_request, (bytes, bytearray)) and raw_request:
        bundle.record_text(
            raw_request.decode("utf-8", errors="replace"),
            filename=f"request-{_slug(exchange_id)}.http",
            kind="http",
            label=f"request {exchange_id[:8]}",
        )

    response_result = await caido_api.view_request(exchange_id, part="response")
    raw_response = getattr(getattr(response_result, "response", None), "raw", None)
    if isinstance(raw_response, (bytes, bytearray)) and raw_response:
        bundle.record_text(
            raw_response.decode("utf-8", errors="replace"),
            filename=f"response-{_slug(exchange_id)}.http",
            kind="http",
            label=f"response {exchange_id[:8]}",
        )


async def copy_evidence_files(
    bundle: Any,
    *,
    sandbox_session: Any,
    paths: list[str] | None,
) -> list[str]:
    """Copy agent-named sandbox files into the finding folder, any type at all.

    The bug decides the evidence: a CSV export for a data-exposure finding, a
    PCAP for a protocol issue, a spreadsheet for a business-logic abuse. So the
    extension is preserved and nothing is parsed — the file lands in the bundle
    exactly as the agent produced it, under its own name.

    Returns warnings for paths that could not be read, so the agent learns the
    evidence is missing while it can still re-do the capture.
    """
    warnings: list[str] = []
    for raw in paths or []:
        if not isinstance(raw, str) or not raw.strip():
            continue
        container_path = raw.strip()
        name = safe_name(container_path)
        if not name:
            warnings.append(f"Ignored evidence path with no filename: {container_path}")
            continue
        data = await read_any_from_sandbox(sandbox_session, container_path)
        if data is None:
            warnings.append(f"Could not read evidence file inside the sandbox: {container_path}")
            continue
        target = bundle.root / name
        try:
            target.write_bytes(data)
        except OSError:
            logger.exception("could not write evidence file %s", target)
            warnings.append(f"Could not store evidence file: {container_path}")
            continue
        bundle.register(target, kind="file", label=name, step=bundle.next_step("file"))
    return warnings


def safe_name(container_path: str) -> str:
    """A filename safe to write into the bundle, taken from the sandbox path."""
    name = re.split(r"[\\/]", container_path.strip())[-1].strip()
    name = re.sub(r'[\x00-\x1f<>:"|?*]', "_", name)
    return name[:120]


async def read_any_from_sandbox(session: Any, container_path: str) -> bytes | None:
    """Read arbitrary bytes out of the sandbox; ``None`` when unreadable.

    ``BaseSandboxSession.read`` is a coroutine returning a binary handle, so the
    handle has to be awaited before it can be drained.
    """
    if session is None:
        return None
    try:
        handle = await session.read(container_path)
        data = handle.read()
    except Exception:
        logger.debug("evidence file not readable at %s", container_path, exc_info=True)
        return None
    if isinstance(data, str):
        return data.encode("utf-8", errors="surrogateescape")
    return bytes(data) if data else None


def _slug(value: str) -> str:
    """Filesystem-safe fragment for an artifact filename."""
    cleaned = re.sub(r"[^A-Za-z0-9]+", "-", value).strip("-").lower()
    return cleaned[:48] or "artifact"
