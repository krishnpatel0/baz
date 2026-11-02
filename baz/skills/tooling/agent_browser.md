---
name: agent_browser
description: agent-browser CLI for headless Chrome via shell. Snapshot-and-ref workflow, click/fill/extract, screenshots, multi-tab, multi-session, network mocking. Pre-installed in the sandbox; invoke via exec_command.
template: jinja
---


# agent-browser core

Fast browser automation CLI for AI agents. Chrome/Chromium via CDP, no
Playwright or Puppeteer dependency. Accessibility-tree snapshots with compact
`@eN` refs let agents interact with pages in ~200-400 tokens instead of
parsing raw HTML.

Pre-installed in the sandbox image. Always invoke via the
``exec_command`` shell tool. The Caido HTTP/HTTPS proxy is already
wired via ``http_proxy`` / ``https_proxy`` env vars — **do not pass
``--proxy``**; agent-browser picks it up automatically and Caido
captures all page traffic. Localhost (CDP) traffic is excluded via
``NO_PROXY=localhost,127.0.0.1``.

Default viewport is 1280×720. For sites that gate behavior on real
desktop dimensions (responsive breakpoints, bot fingerprinting), run
``agent-browser viewport 1920 1080`` once per session.


## The core loop

```bash
agent-browser --session <your-agent-name> open <url>
agent-browser --session <your-agent-name> snapshot -i     # interactive elements
agent-browser --session <your-agent-name> click @e3       # refs from the snapshot
agent-browser --session <your-agent-name> snapshot -i     # refs go stale on any change
```

`@eN` refs are reassigned on every snapshot and stale the moment the page
changes. Claim your own session with `--session <name>` or another agent's
navigation will invalidate your page.

{% if supports_images %}
## Screenshots reach the model only through view_image

`agent-browser screenshot` writes a PNG in the sandbox. The shell command alone
does **not** put the image into your context — chain it:

```bash
exec_command:  agent-browser screenshot
view_image:    {"path": "<path printed on stdout>"}
```

Default output directory is `/workspace/.agent-browser-screenshots/`, which
`view_image` can read. Never write screenshots to `/tmp` — `view_image` rejects
anything outside the workspace root.

If `view_image` errors back (rejected image, "vision not supported"), drive the
page from `snapshot -i` refs and `eval` for DOM state instead.
{% else %}
## You cannot see images

You are running on a text-only model and cannot view images. Screenshots are
only useful to you as a saved file (for example, login evidence to attach to a
finding). Drive the page from `snapshot -i` refs, `eval` for DOM/JS state, and
`get text` for content extraction.
{% endif %}

## Everything else

`load_skill(skills=["tooling/agent_browser_reference"])` for the full CLI:
waits, semantic locators, tabs, frames, dialogs, network mocking, the auth
vault, session persistence, React introspection, video recording, and the
readiness/recovery procedures.
