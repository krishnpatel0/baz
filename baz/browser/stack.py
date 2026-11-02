"""Browser stack — Chrome DevTools MCP over a streamable-HTTP bridge.

The sandbox has Chromium and `agent-browser`, which gives an agent *hands*. It
does not give it *eyes on the inside*: the console, the network bodies, the
DevTools trace, or two independent cookie jars in one process.

`chrome-devtools-mcp` (Google's Chrome DevTools team) supplies exactly that, but
speaks only stdio, while the MCP client lives in the host process. So the
sandbox runs a gateway that republishes the stdio server over streamable HTTP on
a published port, and the host connects to it like any other MCP server.

That is the same shape as the Caido proxy: a service inside the container,
published on a loopback port, resolved from the host with
``session.resolve_exposed_port``.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

from baz.tools.mcp.config import McpConnectionConfig


logger = logging.getLogger(__name__)


CONNECTION_NAME = "browser"
"""MCP connection id agents see in ``list_mcps``."""

CONTAINER_PORT = 48081
"""Port the in-sandbox gateway listens on (Caido owns 48080)."""

IN_CONTAINER_URL = f"http://127.0.0.1:{CONTAINER_PORT}/mcp"

CHROME_BINARY = "/usr/bin/chromium"

# Chromium cannot apply its own sandbox inside this container (no user
# namespaces), and it fails opaquely without being told: the launch dies with
# "Protocol error (Target.setDiscoverTargets): Target closed" and nothing else.
# Verified on Chromium 150 — see BROWSER-RESEARCH.md.
CHROME_ARGS = (
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
)

# Kept off deliberately. The first stops Google telemetry being collected
# during a security assessment; the second stops the CrUX API receiving the
# URLs under test. Neither is acceptable to leave on in this context.
PRIVACY_ARGS = ("--no-usage-statistics", "--no-performance-crux")

# Trimmed to what a pentest actually uses. Excluded categories: performance
# (traces are useful but the insight tools need the CrUX API), memory
# (heap-snapshot forensics, ~14 tools of context cost), extensions, PWA,
# WebMCP, third-party tool discovery. Every tool kept is a real capability;
# every tool dropped is ~150 tokens of schema per turn.
DISABLED_CATEGORIES = (
    "Performance",
    "Memory",
    "Extensions",
    "Pwa",
    "ExperimentalWebmcp",
    "ExperimentalThirdParty",
)

TOOLS_WORTH_CALLING = (
    "evaluate_script",
    "list_console_messages",
    "get_console_message",
    "list_network_requests",
    "get_network_request",
    "take_screenshot",
    "take_snapshot",
    "new_page",
    "navigate_page",
    "list_pages",
    "select_page",
    "close_page",
    "fill",
    "fill_form",
    "click",
    "type_text",
    "press_key",
    "hover",
    "upload_file",
    "handle_dialog",
    "wait_for",
    "emulate",
    "resize_page",
    "screencast_start",
    "screencast_stop",
    "get_css_styles",
)
"""Ranked ahead of the rest in ``search_mcp_tools`` results."""


@dataclass(frozen=True, slots=True)
class BrowserStack:
    """One resolved browser MCP connection for a run."""

    url: str
    """Host-reachable streamable-HTTP endpoint of the gateway."""

    allowed_tools: tuple[str, ...] | None = field(default=None)


WORKSPACE_ROOT = "/workspace"
"""The only directory the browser's file tools may touch.

chrome-devtools-mcp refuses to read or write outside its configured roots, and
defaults to the OS temp dir when the MCP client does not negotiate roots over
the protocol. ``take_screenshot(filePath=...)`` into ``/workspace`` — where
``view_image`` can see it and where the evidence bundle lives — therefore fails
with "Access denied: path is not within any of the configured workspace roots"
unless the root is passed explicitly.
"""


def _server_args() -> list[str]:
    """Arguments for the ``chrome-devtools-mcp`` child of the gateway."""
    args = [
        "--headless",
        "--isolated",
        f"--executablePath={CHROME_BINARY}",
        f"--filesystemRoot={WORKSPACE_ROOT}",
    ]
    args.extend(PRIVACY_ARGS)
    args.extend(f"--chromeArg={arg}" for arg in CHROME_ARGS)
    args.extend(f"--category{category}=false" for category in DISABLED_CATEGORIES)
    return args


def gateway_command() -> str:
    """The shell command the sandbox runs to publish the browser MCP server.

    Wrapped in ``supergateway`` because the server is stdio-only: the gateway
    owns the TCP listener and pipes messages to the child over stdin/stdout.

    The whole child argv is passed as one `--stdio` string, so it must stay
    quote-balanced. Nothing here is user-controlled.
    """
    server = " ".join(["/home/pentester/.npm-global/bin/chrome-devtools-mcp", *_server_args()])
    return (
        "/home/pentester/.npm-global/bin/supergateway"
        f' --stdio "{server}"'
        " --outputTransport streamableHttp"
        " --streamableHttpPath /mcp"
        f" --port {CONTAINER_PORT}"
        # All interfaces, not 127.0.0.1. A loopback-bound listener is not
        # reachable through Docker's published-port proxy, so the host client
        # gets a connection that opens and is then dropped with no response.
        # The port is published to 127.0.0.1 on the host, so this stays off the
        # network; Caido binds the same way inside this image.
        " --host 0.0.0.0"
        " --logLevel info"
        # Without this the gateway serves every request through a fresh child
        # process: a page opened by one call is gone by the next, and every
        # follow-up fails with "No page found". Stateful keeps one child (and
        # therefore one browser) alive per MCP session, which is the whole
        # point of driving a browser over MCP.
        " --stateful"
    )


async def start_in_sandbox(session: Any) -> None:
    """Launch the gateway inside the sandbox, detached from the exec session.

    ``setsid`` is required, not decorative. A plain ``nohup ... &`` inherits the
    exec session's process group and is killed when that session's shell exits —
    the gateway starts, then dies a second later, leaving no listener and often
    no log. Detaching into its own session makes it outlive the call.

    A previous gateway is released first so a restart picks up a changed
    command rather than silently keeping the old one bound to the port. That is
    done by killing whatever holds the port, not by matching the process name:
    ``pkill -f 'supergateway.*48081'`` also matches the shell running this very
    command, so it killed itself before the gateway ever started.
    """
    command = (
        f"fuser -k {CONTAINER_PORT}/tcp 2>/dev/null; sleep 0.2; "
        f"cd /workspace && setsid nohup bash -lc '{gateway_command()}' "
        "> /workspace/.browser-gateway.log 2>&1 < /dev/null & disown; "
        "echo started"
    )
    await session.exec(command)


async def wait_ready(session: Any, *, attempts: int = 60, interval: float = 0.5) -> bool:
    """Poll until the gateway answers a real MCP ``initialize``.

    The gateway's ``--healthEndpoint`` does not serve in the version we pin, so
    readiness is established the honest way: a full JSON-RPC handshake against
    ``/mcp``. That proves the gateway is listening *and* the stdio child is
    alive and speaking MCP — which a bare TCP or health probe would not.
    """
    payload = (
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":'
        '{"protocolVersion":"2025-06-18","capabilities":{},'
        '"clientInfo":{"name":"baz-probe","version":"1"}}}'
    )
    probe = (
        f"curl -fsS -m 3 -X POST http://127.0.0.1:{CONTAINER_PORT}/mcp "
        '-H "Content-Type: application/json" '
        '-H "Accept: application/json, text/event-stream" '
        f"-d '{payload}' 2>/dev/null"
    )
    for _ in range(attempts):
        if "chrome_devtools" in _as_text(await session.exec(probe)):
            return True
        await asyncio.sleep(interval)
    return False


def _as_text(result: Any) -> str:
    """Decode an ``ExecResult`` (or a bare string) to text."""
    raw = getattr(result, "stdout", result)
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "replace")
    if isinstance(raw, str):
        return raw
    return ""


async def connect(session: Any) -> BrowserStack | None:
    """Bring the browser MCP server up and return its host-facing config.

    Returns ``None`` when the gateway cannot be started or does not become
    healthy. A broken browser must never break a scan: the agent still has
    ``agent-browser`` over the shell, so this is a capability upgrade that
    fails open, not a hard dependency.
    """
    try:
        await start_in_sandbox(session)
    except Exception:
        logger.exception("could not start browser MCP gateway")
        return None

    try:
        if not await wait_ready(session):
            logger.warning("browser MCP gateway did not become healthy in time")
            return None
    except Exception:
        logger.exception("browser MCP gateway readiness check failed")
        return None

    try:
        endpoint = await session.resolve_exposed_port(CONTAINER_PORT)
    except Exception:
        logger.exception("could not resolve browser gateway port")
        return None

    scheme = "https" if getattr(endpoint, "tls", False) else "http"
    url = f"{scheme}://{endpoint.host}:{endpoint.port}/mcp"
    logger.info("browser MCP gateway reachable at %s", url)
    return BrowserStack(url=url)


def connection_config(stack: BrowserStack) -> McpConnectionConfig:
    """Wrap a resolved stack as an MCP connection the registry can register."""
    return McpConnectionConfig(
        name=CONNECTION_NAME,
        transport="http",
        url=stack.url,
        active_tools=list(TOOLS_WORTH_CALLING),
        notes=(
            "Chrome DevTools control of the sandbox browser. Use it for anything the "
            "shell cannot see: console output from a payload, full request/response "
            "bodies, and two independent cookie jars in one browser (new_page with "
            "isolatedContext — authenticated-as-A alongside authenticated-as-B, the "
            "IDOR/BOLA primitive). evaluate_script runs JavaScript in the real page "
            "origin, which is how you prove a payload actually executed rather than "
            "merely reflected. Take screenshots through here so the evidence bundle "
            "gets them. The browser is headless and already behind the scan proxy; do "
            "not add a proxy argument."
        ),
    )
