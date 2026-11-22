"""Payload and impact artifacts — the things a triager actually opens.

A report that *describes* a payload is a claim. A report that *ships* the
payload, the run that fired it, and the bytes that came back is evidence.

The problem this solves concretely: an agent tests a SQL injection with a
`curl` one-liner, sees `root:x:0:0` in the response, writes "confirmed SQL
injection, data exfiltration possible" into the report, and the payload and the
stolen row are both gone. The triager then has to reconstruct what was sent, and
the hunter has to reconstruct it first.

So artifacts are stored as files, with the extension that matches what they are,
in the order they were used — in the finding's own folder, flat:

```
vulnerabilities/<id>/
  <id>.md                  the report, citing each artifact by name
  01-request.http          the exact request as sent
  02-exploit.py            a runnable exploit, Python because it was Python
  03-exploit.sh            shell where shell was the tool
  01-sample-records.json   the data actually returned, as found, bounded
```

Two rules that matter more than the format:

**Artifacts keep their real nature.** A Python exploit is a `.py`, a shell
command is a `.sh`, a raw request is `.http`, a captured response is `.txt` or
`.json` depending on what it is. Saving everything as `.txt` throws away the
syntax highlighting a triager uses to read it in thirty seconds.

**Impact data is stored as found.** Proof that `GET /api/users/1` returns another
tenant's record needs the record itself, values intact — a triager judges an
exposed-data finding by looking at what was exposed. Masking it would prove only
that a JSON parser ran. What keeps this responsible is the bound, not the blur:
a handful of representative records with a marker stating how many were observed,
never a bulk dump.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from pathlib import Path


logger = logging.getLogger(__name__)


PAYLOAD_DIRNAME = ""
IMPACT_DIRNAME = ""
"""Both artifact kinds live in the finding folder itself, flat. Kept as names
(not inlined) because the payload store and the impact writer both build paths
from them, and a single empty prefix keeps those call sites identical to the
directory-per-kind layout they replaced."""

MAX_IMPACT_RECORDS = 5
"""Records kept as impact proof. Enough to show it is systematic and not a
one-off page, few enough that the artifact is not itself a data breach."""

MAX_IMPACT_BYTES = 64 * 1024

# What a payload artifact actually is, by how it is written.
_LANGUAGE_BY_SIGNAL: tuple[tuple[str, str, str], ...] = (
    (r"^\s*(import |from \w+ import |def \w+\(|print\()", "python", "py"),
    (r"^\s*<\?php", "php", "php"),
    (r"^\s*(const |let |var |function |await |async )", "javascript", "js"),
    (r"^\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) \S+ HTTP/", "http", "http"),
    (r"#!/bin/(ba)?sh", "shell", "sh"),
    (r"^\s*(curl|wget|nmap|ffuf|sqlmap|nuclei|dalfox|commix)\b", "shell", "sh"),
    (r"^\s*<[a-zA-Z!]", "html", "html"),
    (r"^\s*\{[\s\S]*\}\s*$", "json", "json"),
)

_EXTENSION_BY_LANGUAGE = {
    "python": "py",
    "php": "php",
    "javascript": "js",
    "http": "http",
    "shell": "sh",
    "html": "html",
    "json": "json",
    "text": "txt",
}


def _slug(value: str, *, limit: int = 48) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "-", str(value).lower()).strip("-")
    return (cleaned or "artifact")[:limit]


def classify_language(text: str) -> str:
    """Best-effort language of a payload, for choosing its file extension.

    Order matters: the HTTP request line is checked before the shell rules so a
    raw request is not misfiled as a curl invocation, and Python before shell so
    a script that mentions `curl` inside a subprocess call stays Python.
    """
    for pattern, language, _ext in _LANGUAGE_BY_SIGNAL:
        if re.search(pattern, text, re.MULTILINE):
            return language
    return "text"


def extension_for(language: str) -> str:
    return _EXTENSION_BY_LANGUAGE.get(language, "txt")


@dataclass(slots=True)
class PayloadArtifact:
    """One exact thing that was sent to the target."""

    filename: str
    language: str
    content: str
    label: str
    step: int
    produced: str = ""
    """What this artifact demonstrably caused — the line the triager looks for."""

    def to_wire(self) -> dict[str, Any]:
        return {
            "file": self.filename,
            "language": self.language,
            "label": self.label,
            "step": self.step,
            "produced": self.produced,
        }


@dataclass(slots=True)
class PayloadStore:
    """Writes payload artifacts with sequence prefixes and honest extensions."""

    root: Path
    artifacts: list[PayloadArtifact] = field(default_factory=list)

    @property
    def dir(self) -> Path:
        return self.root / PAYLOAD_DIRNAME

    def add(
        self,
        content: str,
        *,
        label: str,
        step: int | None = None,
        language: str | None = None,
        produced: str = "",
    ) -> PayloadArtifact | None:
        """Save one payload, naming it by position and by what it is.

        ``step`` defaults to the next free number so the artifacts read in the
        order they were used even when the caller does not track steps.
        """
        body = (content or "").rstrip()
        if not body:
            return None
        language = language or classify_language(body)
        step = step if step is not None else len(self.artifacts) + 1
        filename = f"{step:02d}-{_slug(label)}.{extension_for(language)}"

        self.dir.mkdir(parents=True, exist_ok=True)
        (self.dir / filename).write_text(body + "\n", encoding="utf-8")

        artifact = PayloadArtifact(
            filename=filename,
            language=language,
            content=body,
            label=label,
            step=step,
            produced=produced,
        )
        self.artifacts.append(artifact)
        return artifact

    def write_manifest(self) -> None:
        if not self.artifacts:
            return
        payload = {
            "artifacts": [a.to_wire() for a in sorted(self.artifacts, key=lambda a: a.step)],
            "count": len(self.artifacts),
        }
        (self.dir / "manifest.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )


_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}\b"), "<redacted-token>"),
    (re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"), "<redacted-card>"),
    (re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b"), "<redacted-email>"),
)

_SENSITIVE_KEY = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie|session|ssn|"
    r"card|iban|phone|address|birth|private)"
)
"""Field names whose *values* are masked whatever they contain.

Matching on the key rather than the value is what makes this reliable: a
password of `x` looks nothing like a secret, and no pattern on the value would
catch it, but the field is called `password`.
"""


def redact(text: str) -> str:
    """Mask credentials and personal data in a string.

    Not applied to impact samples — those are stored as found, because a
    redacted sample cannot demonstrate that real data was exposed. This exists
    for callers that do want a masked copy, such as a public write-up.
    """
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact_record(record: Any) -> Any:
    """Redact one record by field name first, then by value pattern."""
    if isinstance(record, dict):
        out: dict[str, Any] = {}
        for key, value in record.items():
            if _SENSITIVE_KEY.search(str(key)):
                out[key] = "<redacted>"
            elif isinstance(value, (dict, list)):
                out[key] = redact_record(value)
            elif isinstance(value, str):
                out[key] = redact(value)
            else:
                out[key] = value
        return out
    if isinstance(record, list):
        return [redact_record(item) for item in record]
    return redact(str(record)) if isinstance(record, str) else record


@dataclass(slots=True)
class ImpactEvidence:
    """Sample data proving the demonstrated impact is real."""

    records: list[dict[str, Any]] = field(default_factory=list)
    total_seen: int = 0
    redacted: bool = False
    note: str = ""

    @property
    def truncated(self) -> bool:
        return self.total_seen > len(self.records)


def capture_impact(
    root: Path,
    records: list[Any],
    *,
    label: str = "sample-records",
    total_seen: int | None = None,
    filename: str | None = None,
) -> ImpactEvidence | None:
    """Persist a bounded, marked sample of the data the exploit returned.

    Stored **as found**. Masking the values would defeat the artifact's purpose:
    a triager judges an exposed-data finding by looking at the exposed data —
    that a real email, a real card, a real internal record came back. A redacted
    sample proves only that a JSON parser ran.

    The bounding is what keeps it safe and honest: a handful of representative
    records with an explicit `_note` stating how many were observed, not a bulk
    dump of the breach. The hunter decides what to strip before submitting; the
    evidence is captured intact.
    """
    if not records:
        return None

    kept = records[:MAX_IMPACT_RECORDS]

    body = json.dumps(
        {
            "_note": (
                f"Sample of {len(kept)} record(s) returned by the exploit"
                + (f" out of {total_seen} observed" if total_seen else "")
            ),
            "_truncated": (total_seen or len(records)) > len(kept),
            "records": kept,
        },
        indent=2,
        ensure_ascii=False,
        default=str,
    )
    if len(body) > MAX_IMPACT_BYTES:
        body = body[:MAX_IMPACT_BYTES] + "\n... truncated\n"

    # Flat: the sample sits in the finding folder itself, numbered like every
    # other artifact so the report can cite it by name and it sorts in step order.
    root.mkdir(parents=True, exist_ok=True)
    name = filename or f"{_slug(label)}.json"
    (root / name).write_text(body + "\n", encoding="utf-8")

    return ImpactEvidence(
        records=kept,
        total_seen=total_seen or len(records),
        note=name,
    )
