# view_image

SDK-provided tool that loads an image from the sandbox workspace and
returns it as an image content block for vision-capable models.

- **Implementation:** `agents.sandbox.capabilities.tools.view_image.ViewImageTool`
  (upstream `agents` SDK)
- **Wired in:** `baz/agents/factory.py` — added per-run via the SDK
  `Filesystem` capability.
- **Baz defaults:** screenshots default to
  `/workspace/.agent-browser-screenshots/` via `AGENT_BROWSER_SCREENSHOT_DIR`
  (set in `containers/Dockerfile`; dir is created at container start in
  `containers/docker-entrypoint.sh`).
- **Skill:** screenshot workflow lives in `baz/skills/tooling/agent_browser.md`.
- **Recovery:** vision-not-supported model rejections are auto-recovered
  via `baz.core.sessions.strip_all_images_from_session`, invoked from
  `baz/core/execution.py`.
