"""Browser stack: Chrome DevTools MCP bridged into the sandbox."""

from __future__ import annotations

from baz.browser.stack import (
    CONNECTION_NAME,
    CONTAINER_PORT,
    BrowserStack,
    connect,
    connection_config,
    gateway_command,
)


__all__ = [
    "CONNECTION_NAME",
    "CONTAINER_PORT",
    "BrowserStack",
    "connect",
    "connection_config",
    "gateway_command",
]
