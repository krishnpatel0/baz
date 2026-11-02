"""Sandbox access for host-side tools.

Some tools need to run a command inside the scan's sandbox — `vulnx` for CVE
lookup, for instance — but the tool is invoked on the host, where no session
object exists. This is the same seam the live viewport uses: the runner
registers the session when the sandbox is up, and tools ask here.

Fails closed and quietly. A tool that cannot reach a sandbox returns empty
rather than inventing output; a failed lookup is a thinner queue, never a
fabricated one.
"""

from __future__ import annotations

import logging
from typing import Any


logger = logging.getLogger(__name__)


class _Registry:
    """Holds the live session. A class attribute avoids module-level globals."""

    session: Any = None


def register(session: Any) -> None:
    """Record the live sandbox session for this process."""
    _Registry.session = session


def unregister() -> None:
    _Registry.session = None


def current() -> Any:
    """The registered session, or None when no scan is running."""
    return _Registry.session


async def sandbox_exec(command: str, *, timeout: float = 30.0) -> str:
    """Run a command in the sandbox and return stdout, or "" on any failure.

    Never raises: callers use the result to enrich a queue or a report, and a
    sandbox hiccup must not break the tool that asked.
    """
    session = _Registry.session
    if session is None:
        logger.debug("sandbox_exec(%r): no session registered", command[:60])
        return ""
    try:
        result = await session.exec(f"timeout {int(timeout)} {command}")
    except Exception:  # noqa: BLE001 - enrichment failure, never fatal
        logger.debug("sandbox_exec failed: %s", command[:60], exc_info=True)
        return ""
    raw = getattr(result, "stdout", b"")
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "replace")
    return raw if isinstance(raw, str) else ""
