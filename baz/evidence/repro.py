"""Executable reproduction — run the PoC, believe the exit code.

The problem this solves is the one that makes AI pentest reports untrustworthy:
a finding is filed because the model is confident, and confidence is not
evidence. A report that a human then has to reproduce by hand has moved the
work, not done it.

So a finding must ship a program that demonstrates it. The harness runs that
program here, at file time, against the live sandbox:

- it fails → the report is rejected and the failure goes back to the agent
- it passes → the run and its output are recorded with the finding
- it cannot be run safely → the finding is marked unverified rather than
  silently trusted

The second gate, at end of scan, re-runs every recorded repro from a *fresh*
container. That catches the failure mode this whole layer exists for: a finding
that was true once, in session state that no longer exists.

## Why some findings cannot be replayed

Race conditions, double-spend, IDOR writes, and anything that mutates state are
destructive to re-run: executing the exploit a second time *is* the damage. Those
are marked ``replay_safe=False``, executed exactly once at file time, and
recorded as ``verified_single_run``. The alternative — replaying a double-spend
to prove it — destroys the thing being proven.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


logger = logging.getLogger(__name__)


DEFAULT_TIMEOUT_SECONDS = 120
"""Wall-clock budget for one reproduction.

Generous enough for a network round trip and a browser launch, short enough that
a hung PoC does not eat the scan's budget.
"""

MAX_OUTPUT_CHARS = 8_000
"""How much of the PoC's output is kept. Enough to see what happened, bounded so
a runaway script cannot flood the transcript."""

_UNSAFE_SHELL = re.compile(
    r"""
    rm\s+(-\w*\s+)*-\w*[rf]\w*          # any rm with -r or -f anywhere
  | \bmkfs
  | \bdd\s+.*\bof=/dev/
  | :\(\)\s*\{                        # fork bomb
  | \bshutdown\b
  | \breboot\b
  | \bwipefs\b
  | >\s*/dev/sd
    """,
    re.VERBOSE,
)


class Verdict(StrEnum):
    """Outcome of running a reproduction."""

    REPRODUCED = "reproduced"
    FAILED = "failed"
    TIMEOUT = "timeout"
    UNSAFE = "unsafe"
    NO_REPRO = "no_repro"


@dataclass(slots=True)
class ReproRequest:
    """A repro script plus how it may be run."""

    script: str
    """Bash or Python source. The interpreter is chosen by shebang or extension."""

    language: str = "bash"
    """``bash`` or ``python``."""

    replay_safe: bool = True
    """False for exploits whose re-execution causes the harm they demonstrate
    (race conditions, double-spend, destructive writes). Such a finding is
    verified once, at file time, and never re-run at end of scan."""

    expected_marker: str | None = None
    """Optional substring that must appear in the output for the run to count as
    reproduced. Lets a PoC be strict about *what* it proved, not just that it
    exited 0."""


@dataclass(slots=True)
class ReproResult:
    verdict: Verdict
    exit_code: int | None
    stdout: str
    stderr: str
    duration_ms: int
    reason: str = ""

    @property
    def ok(self) -> bool:
        return self.verdict is Verdict.REPRODUCED

    def to_wire(self) -> dict[str, Any]:
        return {
            "verdict": str(self.verdict),
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "reason": self.reason,
            "stdout": self.stdout[-MAX_OUTPUT_CHARS:],
            "stderr": self.stderr[-MAX_OUTPUT_CHARS:],
        }

    def summary(self, *, limit: int = 400) -> str:
        """One-paragraph description for a tool result or a timeline."""
        head = f"{self.verdict} (exit={self.exit_code}, {self.duration_ms}ms)"
        if self.reason:
            head += f": {self.reason}"
        body = (self.stderr or self.stdout).strip()
        if body:
            head += f"\n{body[:limit]}"
        return head


def is_replay_safe(script: str) -> bool:
    """Conservative static check for a repro that would damage its own target.

    Deliberately narrow. A false positive (marking a safe PoC unsafe) costs a
    single-run verification; a false negative (replaying a destructive PoC at
    end of scan) is a real incident against a real customer.
    """
    return _UNSAFE_SHELL.search(script) is None


_PYTHON_HINTS = ("import ", "from ", "#!/usr/bin/env python")


def _interpreter(language: str, script: str) -> list[str]:
    if language == "python" or script.lstrip().startswith(_PYTHON_HINTS):
        return ["python3"]
    return ["bash"]


def _preflight(request: ReproRequest) -> ReproResult | None:
    """Reject a repro before touching the sandbox."""
    if not request.script.strip():
        return ReproResult(Verdict.NO_REPRO, None, "", "", 0, "empty repro script")
    if not is_replay_safe(request.script):
        return ReproResult(Verdict.UNSAFE, None, "", "", 0, "repro contains a destructive command")
    return None


async def run_repro(
    session: Any,
    request: ReproRequest,
    *,
    workdir: str = "/workspace",
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> ReproResult:
    """Write the repro into the sandbox and run it.

    The script is written to a per-attempt path so two findings cannot overwrite
    each other's PoC, and so the artifact left behind is the exact code that ran.
    """
    guard = _preflight(request)
    if guard is not None:
        return guard

    path = f"{workdir}/.repro/{_slug(request)}.{'py' if _is_python(request) else 'sh'}"
    interpreter = _interpreter(request.language, request.script)
    started = time.monotonic()
    try:
        await _write_via_shell(session, path, request.script)
        command = f"cd {workdir} && timeout {timeout} {' '.join(interpreter)} {path} 2>&1"
        result = await session.exec(command)
    except Exception as exc:
        logger.exception("reproduction could not run")
        elapsed = int((time.monotonic() - started) * 1000)
        return ReproResult(Verdict.FAILED, None, "", str(exc), elapsed, "could not run")

    duration_ms = int((time.monotonic() - started) * 1000)
    stdout = _text(getattr(result, "stdout", b""))
    stderr = _text(getattr(result, "stderr", b""))
    exit_code = getattr(result, "exit_code", None)

    if exit_code == 124:
        return ReproResult(
            Verdict.TIMEOUT, exit_code, stdout, stderr, duration_ms, f"exceeded {timeout}s"
        )

    if exit_code != 0:
        return ReproResult(Verdict.FAILED, exit_code, stdout, stderr, duration_ms, "non-zero exit")

    if request.expected_marker and request.expected_marker not in (stdout + stderr):
        return ReproResult(
            Verdict.FAILED,
            exit_code,
            stdout,
            stderr,
            duration_ms,
            f"exit 0 but marker {request.expected_marker!r} not in output",
        )

    return ReproResult(Verdict.REPRODUCED, exit_code, stdout, stderr, duration_ms)


async def _write_via_shell(session: Any, path: str, body: str) -> None:
    """Write the script byte-for-byte through a quoted heredoc.

    Quoted, so nothing in the repro is expanded by the shell on the way in: a
    payload containing ``$``, backticks or quotes has to survive intact or the
    thing we execute is not the thing that was filed.
    """
    delimiter = "BAZ_REPRO_EOF"
    await session.exec(f"mkdir -p {path.rsplit('/', 1)[0]}")
    await session.exec(f"cat > {path} <<'{delimiter}'\n{body}\n{delimiter}")


def _is_python(request: ReproRequest) -> bool:
    return _interpreter(request.language, request.script) == ["python3"]


def _slug(request: ReproRequest) -> str:
    return hashlib.sha256(request.script.encode("utf-8", "replace")).hexdigest()[:16]


def _text(raw: Any) -> str:
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "replace")
    return raw if isinstance(raw, str) else ""
