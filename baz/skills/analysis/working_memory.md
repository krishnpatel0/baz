---
name: working_memory
description: How to work so nothing is lost when old tool output is forgotten — what to record, when, and in which of the four durable stores.
template: jinja
---

# Working Memory

Your conversation is scratch space, not an archive. Old tool output **is** dropped
as a run progresses — a 40,000-token `ffuf` dump from twenty turns ago is not
re-sent, because it is not what you reason with; the *conclusion* you drew from
it is.

That only works if the conclusion is written down. This skill is the discipline
that makes it safe.

## The rule

> **Before you move on from something, write down what it told you.**

Not the output — the finding. "ffuf on /api returned 340 paths; /admin (403),
/api/v2 (200), /backup.sql (200, 1.2 MB)" is durable. The 340-line JSON is not,
and it will be evicted.

If you find yourself re-running a command to see its output again, that is the
signal you failed to record it the first time. Re-running costs a turn and
re-bills the scan; a note costs nothing.

## The four durable stores

Everything you learn goes in one of these. Nothing else survives.

| Store | Use for | Tool |
|---|---|---|
| **Notes** | facts the next agent needs: an endpoint inventory, working credentials, a rate-limit quirk, a technology version | `create_note` / `update_note` |
| **Coverage** | what you tested and how it closed — including what came back clean | `record_coverage` |
| **Threat model** | corrections to what the target's trust boundaries actually are | `amend_threat_model` |
| **Findings** | a validated vulnerability, with its evidence | `create_vulnerability_report` |

**Notes are shared.** Every other agent in this scan reads them. Write for a
reader who was not here and cannot see your transcript: name the host, the path,
the parameter. "Found a weak endpoint" is useless to the agent after you.

## What must be recorded, always

These are not optional, because losing them loses work another agent would
otherwise redo:

| Moment | Record |
|---|---|
| You discovered an endpoint, host or parameter | note: the inventory, with what it does |
| You found a credential, token or key | note: where it works, and its scope |
| You ruled something out | coverage: `ruled_out` + the control that closed it |
| You hit a WAF, rate limit or block | note: the shape, so the next agent does not retry blindly |
| You identified a version | note: the component, version, and how you know |
| You filed a finding | the report itself; the raw output is not the evidence, the bundle is |
| You are about to run a long scan | note: what you are about to check, so the result lands somewhere if you are interrupted |

## What not to record

- Raw tool output — it is on disk already (`artifact://`, the workspace spill,
  and the proxy history). Point at it; do not copy it.
- Things already in the threat model or an existing note. `update_note` rather
  than filing a second one.
- Reasoning you are still working through. Notes are for conclusions; the
  transcript holds the working.

## The loop

```
run a scan          →  read the result
                       ↓
                    write down what it means    (note / coverage)
                       ↓
                    act on it
                       ↓
                    ... older output ages out of context
                       ↓
                    the note is what remains — and it is enough
```

## Why this makes the scan better, not just cheaper

A scan that records as it goes is one where a later agent starts from what you
learned rather than from nothing. The alternative — hoping the transcript
survives — fails in two ways: the context window caps how much can survive, and
what survives is raw bytes nobody will re-read.

Recording is how one agent's work becomes the next agent's starting point. Not
recording is how the same target gets enumerated three times in one run.
