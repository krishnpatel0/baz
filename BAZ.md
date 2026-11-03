# Baz

A fork of Strix, extended into a deeper and more aggressive bug bounty tool.

## Where things are

This repository is the **fork**. It is local only:

- **Branch:** `havoc` — 46 commits ahead of upstream `main`
- **Location:** `K:/bugggs/project-pentest/strix`
- **Remote:** `origin` is upstream (`github.com/usestrix/strix`) and is **read-only
  in practice** — there is no fork on GitHub, no `origin/havoc`, and nothing has
  been pushed anywhere. Do not push to `origin`.

The **documentation is not in this repository.** It lives beside it, at:

```
K:/bugggs/project-pentest/docs/
```

Twelve files. Start with `12-where-things-live.md` for a full path map, or
`README.md` for the index.

Kept outside the repo on purpose: this is a fork of someone else's project, and
adding a `docs/` tree would collide with upstream on every merge.

## Building

```bash
cd strix
uv run baz --version                    # .baz/1.7.0
docker build -f containers/Dockerfile -t baz-sandbox:dev .
cd baz/interface/tui && go build ./...  # the Go TUI
```

Full build, run, and test instructions: `docs/08-operations.md`.

## Running

```powershell
$env:BAZ_LLM = "openai/deepseek-v4-mod"
$env:LLM_API_BASE = "https://api.hackerai.sh/v1"
$env:LLM_API_KEY = "<key>"
$env:BAZ_IMAGE = "baz-sandbox:dev"
uv run baz --target "*.example.com" --scan-mode deep
```

Wildcard targets must be quoted, or the shell globs them before Baz sees them.

## Not in this repo

- The docs (`../docs/`)
- Scan output (`baz_runs/` — local, per-run)
- The Docker image (local Docker only, tag `baz-sandbox:dev`)
- Any remote backup — nothing is pushed
