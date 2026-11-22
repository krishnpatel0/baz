"""A bootstrap that dies mid-setup must not leave its transport behind.

The bootstrap now runs concurrently with the scan start, so teardown can
cancel it at any await — including inside ``Client.connect()``, where the
client exists but no caller will ever see it to close it.
"""

from __future__ import annotations

import asyncio
import sys
import types
from typing import Any

import pytest

from baz.runtime.caido_bootstrap import bootstrap_caido


class _FakeExecResult:
    stderr = b""
    exit_code = 0

    def __init__(self, stdout: str) -> None:
        self.stdout = stdout

    def ok(self) -> bool:
        return True


class _FakeSession:
    async def exec(self, *_args: Any, **_kwargs: Any) -> _FakeExecResult:
        return _FakeExecResult('{"data":{"loginAsGuest":{"token":{"accessToken":"t"}}}}')


class _FakeClient:
    def __init__(self, connect_error: BaseException) -> None:
        self.connect_error = connect_error
        self.closed = False

    async def connect(self) -> None:
        raise self.connect_error

    async def aclose(self) -> None:
        self.closed = True


async def _bootstrap_expecting(
    monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> _FakeClient:
    """Run a bootstrap whose ``connect()`` fails with ``error``."""
    client = _FakeClient(error)
    # The SDK is imported inside bootstrap_caido (it is slow to import), so the
    # fakes are injected as the modules it imports.
    sdk = types.ModuleType("caido_sdk_client")
    sdk.Client = lambda *_a, **_k: client  # type: ignore[attr-defined]
    sdk.TokenAuthOptions = lambda token: token  # type: ignore[attr-defined]
    sdk_types = types.ModuleType("caido_sdk_client.types")
    sdk_types.CreateProjectOptions = lambda **_k: None  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "caido_sdk_client", sdk)
    monkeypatch.setitem(sys.modules, "caido_sdk_client.types", sdk_types)

    with pytest.raises(type(error)):
        await bootstrap_caido(
            _FakeSession(),  # type: ignore[arg-type]
            host_url="http://host",
            container_url="http://container",
        )
    return client


async def test_cancellation_during_connect_closes_the_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = await _bootstrap_expecting(monkeypatch, asyncio.CancelledError())
    assert client.closed


class _FakeProjectSdk:
    """Records project create/select calls for the reuse-vs-create contract."""

    def __init__(self, existing: list[Any]) -> None:
        self._existing = existing
        self.created = 0
        self.selected: list[str] = []

    async def list(self) -> list[Any]:
        return self._existing

    async def create(self, _options: Any) -> Any:
        self.created += 1
        return _Project("created")

    async def select(self, project_id: str) -> Any:
        self.selected.append(project_id)
        return _Project(project_id)


class _Project:
    def __init__(self, project_id: str) -> None:
        self.id = project_id


class _FakeProjectClient:
    def __init__(self, projects: _FakeProjectSdk) -> None:
        self.project = projects


async def test_bootstrap_reuses_the_entrypoint_project(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A second create fails for guests (exactly one project allowed), so the
    bootstrap must reuse the project the entrypoint already selected."""
    projects = _FakeProjectSdk([_Project("entrypoint-project")])
    client = _FakeProjectClient(projects)

    sdk = types.ModuleType("caido_sdk_client")
    sdk.Client = lambda *_a, **_k: client  # type: ignore[attr-defined]
    sdk.TokenAuthOptions = lambda token: token  # type: ignore[attr-defined]
    sdk_types = types.ModuleType("caido_sdk_client.types")
    sdk_types.CreateProjectOptions = lambda **_k: None  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "caido_sdk_client", sdk)
    monkeypatch.setitem(sys.modules, "caido_sdk_client.types", sdk_types)

    async def _noop(*_a: Any, **_k: Any) -> None:
        return None

    client.connect = _noop  # type: ignore[attr-defined]
    client.aclose = _noop  # type: ignore[attr-defined]

    returned = await bootstrap_caido(
        _FakeSession(),  # type: ignore[arg-type]
        host_url="http://host",
        container_url="http://container",
    )

    assert projects.created == 0
    assert projects.selected == ["entrypoint-project"]
    assert returned is client


async def test_bootstrap_creates_when_no_project_exists() -> None:
    from baz.runtime.caido_bootstrap import _select_or_create_project

    projects = _FakeProjectSdk([])
    resolved = await _select_or_create_project(_FakeProjectClient(projects))  # type: ignore[arg-type]

    assert projects.created == 1
    assert resolved.id == "created"


async def test_failed_connect_closes_the_client(monkeypatch: pytest.MonkeyPatch) -> None:
    client = await _bootstrap_expecting(monkeypatch, RuntimeError("no listener"))
    assert client.closed
