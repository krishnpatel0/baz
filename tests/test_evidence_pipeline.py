"""Tests for the flat evidence pipeline: bundle layout, citation and gathering.

Covers what the request asked for and nothing else:

- one flat folder per finding under ``vulnerabilities/``, the ``.md`` beside
  its artifacts, no subdirectories;
- any file type attachable by the agent, extension preserved;
- the report citing screenshots and artifacts by name and number;
- collection happening by default at filing time, from the sandbox.
"""

from __future__ import annotations

import asyncio
import io
import json
from pathlib import Path
from typing import Any

import pytest
from PIL import Image

from baz.evidence import open_bundle
from baz.evidence.backfill import backfill_run_evidence
from baz.evidence.gather import (
    collect_screenshots,
    copy_evidence_files,
    read_any_from_sandbox,
    safe_name,
)
from baz.report.writer import _report_path, render_vulnerability_md, write_vulnerabilities


def _png(size: tuple[int, int] = (120, 80)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, (12, 34, 56)).save(buf, "PNG")
    return buf.getvalue()


class FakeSession:
    """Minimal stand-in for ``BaseSandboxSession``: async ``read`` and ``ls``."""

    def __init__(self, files: dict[str, bytes], listing: dict[str, list[Any]] | None = None):
        self.files = files
        self.listing = listing or {}
        self.reads: list[str] = []

    async def read(self, path: Any, **kwargs: Any) -> io.BytesIO:
        del kwargs
        key = str(path)
        self.reads.append(key)
        if key not in self.files:
            raise FileNotFoundError(key)
        return io.BytesIO(self.files[key])

    async def ls(self, path: Any, **kwargs: Any) -> list[Any]:
        del kwargs
        key = str(path)
        if key not in self.listing:
            raise FileNotFoundError(key)
        return self.listing[key]


class _Entry:
    def __init__(self, path: str):
        self.path = path


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    return tmp_path / "baz_runs" / "run-1"


def test_bundle_is_flat_and_report_sits_inside(run_dir: Path) -> None:
    bundle = open_bundle(run_dir, "vuln-0001", "IDOR on /api/users/{id}")
    bundle.capture_screenshot(_png(), label="initial state", url="https://t/x")
    bundle.record_payload("GET / HTTP/1.1", label="request", step=1, language="http")
    bundle.record_impact([{"id": 2}], total_seen=9)
    sealed = bundle.seal({"id": "vuln-0001", "title": "IDOR"})

    assert sealed.parent.name == "vulnerabilities"
    assert not [p for p in sealed.rglob("*") if p.is_dir()]

    report = {
        "id": "vuln-0001",
        "title": "IDOR on /api/users/{id}",
        "severity": "high",
        "timestamp": "2026-11-22T00:00:00Z",
        "description": "d",
        "impact": "i",
        "evidence_bundle": str(sealed),
    }
    write_vulnerabilities(run_dir, [report], set())

    md = _report_path(run_dir, report)
    assert md == sealed / "vuln-0001.md"
    assert md.is_file()


def test_report_cites_each_artifact_by_name_and_number(run_dir: Path) -> None:
    bundle = open_bundle(run_dir, "vuln-0002", "IDOR")
    bundle.capture_screenshot(_png(), label="bob reads invoice", url="https://t/x")
    bundle.record_payload("print(1)", label="exploit", step=2, language="python")
    extra = bundle.root / "03-dump.csv"
    extra.write_bytes(b"id,email\n2,alice@t\n")
    bundle.register(extra, kind="file", label="dump.csv", step=3)
    sealed = bundle.seal({"id": "vuln-0002", "title": "IDOR"})

    body = render_vulnerability_md(
        {
            "id": "vuln-0002",
            "title": "IDOR",
            "severity": "high",
            "timestamp": "2026-11-22T00:00:00Z",
            "description": "d",
            "impact": "i",
            "evidence_bundle": str(sealed),
        }
    )

    assert "![Screenshot 1" in body
    assert "**Payload 1**" in body
    assert "01-request.http" not in body  # not filed for this finding
    assert "02-exploit.py" in body
    assert "03-dump.csv" in body
    assert "**Artifact 1**" in body

    # Every link is a bare filename that exists beside the report.
    for target in [p for p in sealed.iterdir() if p.is_file()]:
        if target.suffix in {".md", ".json"}:
            continue
        assert f"]({target.name})" in body


def test_arbitrary_file_types_are_attachable(run_dir: Path) -> None:
    bundle = open_bundle(run_dir, "vuln-0003", "Business logic abuse")
    payload = b"PK\x03\x04not-really-xlsx"
    session = FakeSession({"/workspace/out/report.xlsx": payload})

    warnings = asyncio.run(
        copy_evidence_files(
            bundle,
            sandbox_session=session,
            paths=["/workspace/out/report.xlsx"],
        )
    )

    assert warnings == []
    stored = bundle.root / "report.xlsx"
    assert stored.read_bytes() == payload
    assert any(c.path == "report.xlsx" and c.kind == "file" for c in bundle.captures)


def test_missing_file_warns_instead_of_failing(run_dir: Path) -> None:
    bundle = open_bundle(run_dir, "vuln-0004", "x")
    session = FakeSession({})

    warnings = asyncio.run(
        copy_evidence_files(bundle, sandbox_session=session, paths=["/workspace/gone.csv"])
    )
    assert warnings and "gone.csv" in warnings[0]
    assert not (bundle.root / "gone.csv").exists()


def test_screenshots_are_gathered_by_default(run_dir: Path) -> None:
    bundle = open_bundle(run_dir, "vuln-0005", "XSS")
    shot = "/workspace/.agent-browser-screenshots/alert-fires.png"
    session = FakeSession(
        {shot: _png()},
        listing={"/workspace/.agent-browser-screenshots": [_Entry("alert-fires.png")]},
    )

    collected = asyncio.run(collect_screenshots(bundle, session))

    assert collected == 1
    stored = [c for c in bundle.captures if c.kind == "screenshot"]
    assert len(stored) == 1
    assert (bundle.root / stored[0].path).is_file()


def test_screenshot_directory_absent_is_not_an_error(run_dir: Path) -> None:
    bundle = open_bundle(run_dir, "vuln-0006", "x")

    assert asyncio.run(collect_screenshots(bundle, FakeSession({}))) == 0


def test_read_any_from_sandbox_returns_bytes_and_none() -> None:

    session = FakeSession({"/workspace/a.bin": b"\x00\x01\x02"})
    assert asyncio.run(read_any_from_sandbox(session, "/workspace/a.bin")) == b"\x00\x01\x02"
    assert asyncio.run(read_any_from_sandbox(session, "/workspace/nope")) is None
    assert asyncio.run(read_any_from_sandbox(None, "/workspace/a.bin")) is None


def test_safe_name_strips_paths_and_control_characters() -> None:
    assert safe_name("/workspace/out/report.csv") == "report.csv"
    assert safe_name("C:\\temp\\a b.xlsx") == "a b.xlsx"
    assert safe_name("/workspace/od:d.csv") == "od_d.csv"
    assert safe_name("") == ""


def test_sealed_artifact_list_drives_the_report(run_dir: Path) -> None:
    """A file on disk that was never registered must not be cited."""
    bundle = open_bundle(run_dir, "vuln-0007", "x")
    (bundle.root / "09-stray.csv").write_bytes(b"a,b\n")
    sealed = bundle.seal({"id": "vuln-0007", "title": "x"})

    body = render_vulnerability_md(
        {
            "id": "vuln-0007",
            "title": "x",
            "severity": "low",
            "timestamp": "2026-11-22T00:00:00Z",
            "description": "d",
            "impact": "i",
            "evidence_bundle": str(sealed),
        }
    )
    assert "09-stray.csv" not in body


def test_finding_without_bundle_still_renders_a_report(run_dir: Path) -> None:
    run_dir.mkdir(parents=True)
    report = {
        "id": "vuln-0008",
        "title": "No bundle",
        "severity": "low",
        "timestamp": "2026-11-22T00:00:00Z",
        "description": "d",
        "impact": "i",
    }
    write_vulnerabilities(run_dir, [report], set())
    assert (run_dir / "vulnerabilities" / "vuln-0008.md").is_file()
    assert "## Screenshots" not in render_vulnerability_md(report)


def test_index_csv_points_at_the_report_inside_the_bundle(run_dir: Path) -> None:
    bundle = open_bundle(run_dir, "vuln-0009", "x")
    sealed = bundle.seal({"id": "vuln-0009", "title": "x"})
    report = {
        "id": "vuln-0009",
        "title": "x",
        "severity": "medium",
        "timestamp": "2026-11-22T00:00:00Z",
        "description": "d",
        "impact": "i",
        "evidence_bundle": str(sealed),
    }
    write_vulnerabilities(run_dir, [report], set())

    csv_text = (run_dir / "vulnerabilities.csv").read_text(encoding="utf-8")
    assert "vulnerabilities/vuln-0009/vuln-0009.md" in csv_text
    index = json.loads((run_dir / "vulnerabilities.json").read_text(encoding="utf-8"))
    assert index[0]["id"] == "vuln-0009"


def test_backfill_attaches_evidence_to_a_bundleless_finding(run_dir: Path) -> None:
    """A finding filed before the collection step gains evidence at finalize."""
    run_dir.mkdir(parents=True)
    shot = "/workspace/.agent-browser-screenshots/late.png"
    session = FakeSession(
        {shot: _png()},
        listing={"/workspace/.agent-browser-screenshots": [_Entry("late.png")]},
    )
    report = {
        "id": "vuln-0010",
        "title": "Filed before the wiring",
        "severity": "high",
        "timestamp": "2026-11-22T00:00:00Z",
        "description": "d",
        "impact": "i",
    }

    enriched = asyncio.run(
        backfill_run_evidence(run_dir=run_dir, reports=[report], sandbox_session=session)
    )

    assert enriched == 1
    assert report["evidence_bundle"]
    bundle_root = Path(str(report["evidence_bundle"]))
    assert (bundle_root / "finding.json").is_file()
    assert list(bundle_root.glob("*.png"))

    # The report now cites the screenshot it gained.
    body = render_vulnerability_md(report)
    assert "## Screenshots" in body
    assert "![Screenshot 1" in body


def test_backfill_leaves_a_sealed_bundle_untouched(run_dir: Path) -> None:
    bundle = open_bundle(run_dir, "vuln-0011", "Already sealed")
    bundle.capture_screenshot(_png(), label="original", url="")
    sealed = bundle.seal({"id": "vuln-0011", "title": "Already sealed"})
    report = {
        "id": "vuln-0011",
        "title": "Already sealed",
        "severity": "low",
        "timestamp": "2026-11-22T00:00:00Z",
        "description": "d",
        "impact": "i",
        "evidence_bundle": str(sealed),
    }
    session = FakeSession(
        {"/workspace/.agent-browser-screenshots/second.png": _png()},
        listing={"/workspace/.agent-browser-screenshots": [_Entry("second.png")]},
    )

    enriched = asyncio.run(
        backfill_run_evidence(run_dir=run_dir, reports=[report], sandbox_session=session)
    )

    assert enriched == 0
    assert not (sealed / "second.png").exists()
    assert len(list(sealed.glob("*.png"))) == 1


def test_backfill_without_sandbox_is_a_noop(run_dir: Path) -> None:
    result = asyncio.run(backfill_run_evidence(run_dir=run_dir, reports=[], sandbox_session=None))
    assert result == 0
