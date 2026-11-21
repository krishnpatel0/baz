# Baz

An autonomous AI penetration-testing tool, forked from Strix
(<https://github.com/usestrix/strix>) and extended with a
deeper, more aggressive bug-bounty workflow: browser DevTools control, evidence
bundles, a reproduction gate, and submission-ready exports.

## Where things are

The canonical repository is **`https://github.com/krishnpatel0/baz`**, branch
`main`. A local working clone lives at `K:/bugggs/project-pentest/strix`.

- **Branch:** `baz`, published as `main`
- **Push remote:** `baz` → `https://github.com/krishnpatel0/baz.git`
- **`origin`** is upstream Strix and is **read-only in practice** — do not push
  to it; it targets a repository we do not own.

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
cd baz
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
- The Docker image (built locally, tag `baz-sandbox:dev`)

## License

Baz is a derivative work of Baz and is distributed under the Apache License,
Version 2.0. The original copyright notices and the `LICENSE` file are retained;
see `LICENSE` and the Acknowledgements section of `README.md`. Only run Baz
against systems you own or have explicit written permission to test.
