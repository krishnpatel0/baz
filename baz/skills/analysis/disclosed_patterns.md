# Disclosed Patterns — What Actually Wins

> Distilled from publicly disclosed reports and practitioner writeups. The point
> is not "test for IDOR" — it is the specific mutations that survive a naive fix,
> because the naive fix is what you are usually testing against.
>
> Every section ends in a **Testable patterns** list. Those are the checks an
> agent should run; the prose above them is why.

---

## IDOR / BOLA

### What works

**The fix is usually incomplete, and the incompleteness is the finding.** A
developer who patches IDOR typically adds an ownership check to the endpoint
they were shown, or to the newest API version. The same object is reachable
through a sibling path that was never touched.

**Parameter shape mutations beat value guessing.** When a straight ID swap
returns 403, the authorization check often runs on the unwrapped scalar while the
data layer consumes the wrapped value.

| Mutation | Example | Why it survives |
|---|---|---|
| wrap in array | `{"id":19}` → `{"id":[19]}` | ORM unwraps; check ran on the scalar |
| array of targets | `{"id":[1234,1235]}` | check runs on the first element only |
| float | `id=1234.0` | type coercion skips the check |
| leading zeros | `id=00001234` | parser differential: validator vs driver |
| negative / zero | `id=-1`, `id=0` | comparator fails; sometimes returns the default row |
| delimiter string | `id="1234,1235"` | server-side comma split |
| rename the key | `album_id` → `account_id` | undocumented override honored unchecked |

**HPP is the highest-yield single trick.** Send the parameter twice and see which
layer reads which copy: PHP/Tomcat take the first, Rails takes the last, Node
makes an array, .NET concatenates. Auth middleware reading one and the data layer
reading the other is a complete bypass.

**Add an ID to a request that has none.** Endpoints that implicitly use the
session user (`/api/MyPictureList`) often honor an unexpected `?user_id=` and
skip their "current user" shortcut.

**Method and content-type route to different handlers.** A `POST` to a
`GET`-only URL may hit an orphaned handler with no middleware. Swapping
`application/json` → `application/xml` → `text/x-json` changes which parser —
and sometimes which auth path — runs.

**UUIDs are not access control.** They leak in public profiles, share links,
invite emails, comment/mention payloads, API responses you already receive,
Wayback snapshots, and search-engine indexes. Harvest before guessing.

**Unauthenticated IDOR is the jackpot.** Always retry every IDOR with the
`Authorization` header stripped. No account required, mass-scrape-ready.

**Cross-tenant is the modern SaaS variant.** Change `organizationId` in a PUT
body and write into another tenant. The endpoint checks *authentication* and not
*which tenant the token belongs to*.

### What gets rejected

- "IDOR" where both IDs belong to you
- A 403 reported as a finding
- Sequential-ID enumeration with no proof you read another user's data
- Reporting a staging host out of scope
- Bulk data dumps: the sample is the proof, not the dump

### Golden examples

| Report | Bug | Why it worked |
|---|---|---|
| H1 #915114 (Automattic/CrowdSignal) | IDOR editing users → ATO | showed the full path to account takeover, not just the read |
| H1 #3869124 (Weblate) | **Unauthenticated** IDOR modifying payment billing info | no account needed; modification not just read |
| H1 #1626508 (DoD) | IDOR downloading documents, PII of soldiers | impact framed as PII exposure at scale, sample provided |
| H1 #2967032 (DoD) | IDOR exposing PII of tens of thousands | counted the affected population |

### Testable patterns

1. For every object ID in your traffic: replay with User B's session, then with
   no session.
2. Replay with `{"id":19}` → `{"id":[19]}` → `{"id":[19,20]}` → `id=19.0`.
3. Duplicate the parameter: `?id=<mine>&id=<theirs>`.
4. Add `?user_id=<theirs>` to endpoints that have no ID parameter.
5. Method sweep: `GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS` on every endpoint.
6. Content-type sweep: json ↔ xml ↔ form ↔ text-json.
7. Try `me`/`current`/`self` → numeric ID swap.
8. Base64-decode every opaque path segment; look for a linear region.
9. Harvest IDs from JS bundles, `.map` files, autocomplete endpoints, error messages.
10. Retry everything unauthenticated.

---

## Authentication Bypass / Account Takeover

### What works

**The reset flow is the softest target in any app.** Tokens that are
predictable, reusable, or not bound to the account; host-header injection
poisoning the reset link; response manipulation revealing the token.

**OAuth/OIDC redirect_uri matching is usually prefix- or regex-based.**
`https://app.com/callback` accepting `https://app.com/callback.evil.com`,
`https://app.com@evil.com`, or `https://evil.com/app.com/callback` is the
classic. Also try path traversal in the redirect: `/callback/../evil`.

**Session tokens that never rotate** after login, password change, or privilege
change are a finding — especially when combined with a logout that does not
invalidate server-side.

**2FA bypass via response manipulation**: intercept the "OTP required" response
and change `{"mfa":true}` → `{"mfa":false}`, or the OTP-verify response
`{"success":false}` → `{"success":true}`. Works more often than it should
because client-side routing trusts the response.

**2FA bypass via enrollment gap**: enable 2FA, then remove it via an endpoint
that does not check the current OTP.

### What gets rejected

- Missing rate limit on login without demonstrating the outcome (credential
  stuffing at scale)
- Session fixation where you cannot show a victim path
- Logout CSRF
- "Password policy weak" without an exploit

### Testable patterns

1. Reset flow: request reset for your account, capture the token, then try it
   for a second account; try reusing it after password change.
2. Host-header injection in reset: `X-Forwarded-Host: evil.tld` on the reset
   request, then check the email link (or the response, if it reflects).
3. OAuth: `redirect_uri` with `@`, `.evil.com`, path traversal, and the
   registered URI plus `?next=evil`.
4. Response manipulation: flip boolean fields in auth responses; re-submit.
5. Session: capture a session token, change the password, replay the token.
6. 2FA: enroll, then try disabling via API without the current OTP.
7. JWT: `alg:none`, `alg:HS256` with the public key as secret, `kid` injection.

---

## SSRF

### What works

**Blind SSRF to an internal metadata endpoint is the highest-value version.**
AWS `169.254.169.254/latest/meta-data/iam/security-credentials/` returning a role
name is a critical finding without ever touching the credential value.

**URL parser differentials defeat allowlists.** Where the validator and the
fetcher disagree:

| Payload shape | Disagreement |
|---|---|
| `http://expected.com@evil.com/` | validator reads host=expected, fetcher reads evil |
| `http://evil.com#@expected.com` | fragment handling |
| `http://expected.com.evil.com` | suffix vs exact match |
| `http://169.254.169.254` in decimal/octal/hex | `http://2852039166/` |
| `http://[::ffff:169.254.169.254]` | IPv6-mapped |
| DNS rebinding | resolve to allowed IP, then to internal |
| redirect chain | allowlisted URL 302s to internal |

**The feature is the vector.** Any "import from URL", "webhook test", "fetch
avatar", "PDF renderer", "URL preview" is a fetcher. Those are the endpoints.

### What gets rejected

- SSRF to `127.0.0.1` with no demonstrated service behind it
- SSRF blocked by egress rules — report the *attempt* as informational at best
- Metadata access without showing what the endpoint returned

### Testable patterns

1. Every URL-accepting parameter: point at a collaborator, confirm callback.
2. Then point at `169.254.169.254/latest/meta-data/` and read only the role name.
3. Try the allowlist bypass table above against any host check.
4. Try redirects: your collaborator 302s to the internal target.
5. Try non-HTTP schemes: `file://`, `gopher://`, `dict://`.

---

## SQL Injection

### What works

**Boolean differential is the reliable oracle**, not error messages. Error-based
is nice when it fires; boolean works when errors are suppressed.

**The injection point is rarely the obvious one.** Headers (`X-Forwarded-For`
logged into a query), sort/order parameters (`ORDER BY <input>` cannot be
parameterized), and JSON path expressions are where real SQLi hides.

**Second-order**: input stored safely, then concatenated in a background job or
report generator. Test by storing a payload then triggering the feature that
consumes it.

**WAF bypass is usually encoding plus comment placement**: `/*!50000SELECT*/`,
`UN/**/ION`, URL double-encoding, unicode normalization.

### Testable patterns

1. Boolean pair on every parameter: `' AND 1=1-- -` vs `' AND 1=2-- -`.
2. Time-based on the same: `'; SELECT pg_sleep(5)-- -` with a control request.
3. Order-by: `?sort=id,(select 1)`, `?sort=1 AND 1=1`.
4. Headers: `X-Forwarded-For: 1' AND 1=1-- -` on every request.
5. Second-order: store `'; --` in a name field, then trigger the export/report.
6. Prove with data: table name plus one row, not "data returned".

---

## XSS

### What works

**Stored XSS in an admin-viewed field is the payout.** The victim is the person
who can act, so impact is immediate. Look for fields rendered in an admin panel:
support tickets, user profiles, filenames, order notes.

**Context determines payload, not the other way round.** Classify the sink first
(HTML node, attribute, JS string, URL, CSS) then pick the smallest payload for
that context.

**Blind XSS via out-of-band** when the render target is invisible to you — an
admin dashboard, a log viewer, an email client.

**mXSS survives sanitizers** because the browser re-parses after the sanitizer
runs. `<noscript><p title="</noscript><img src=x onerror=alert(1)>">` and
similar.

### What gets rejected

- Self-XSS
- Alert-box-only proof with no session impact
- Reflected XSS with no victim path
- Missing CSP reported as XSS

### Testable patterns

1. Every reflected parameter: send `<svg onload=alert(1)>` and a canary.
2. Every stored field: submit, then view as admin/second user.
3. Confirm execution, not reflection: `evaluate_script` returning `true` from a
   fired handler.
4. Context-classify before payload selection; try the polyglot only after.
5. Try mXSS payloads against any field that appears sanitized.

---

## Business Logic / Race Conditions

### What works

**Race conditions win where the invariant is checked-then-used.** Apply coupon →
check balance → deduct. Fire N requests in parallel and the check passes for
several before the deduction lands. Single-packet attack (HTTP/2) makes this far
more reliable than threaded requests.

**Price and quantity manipulation**: negative quantity, `price=0`, currency
confusion, integer overflow on totals.

**Workflow bypass**: call step 3 without step 2; replay a completed step.

### Testable patterns

1. Any coupon/refund/transfer: 20 parallel identical requests, count successes.
2. Any multi-step flow: call each step out of order.
3. Any price field: send negative, zero, huge, and a different currency.
4. Any trial/limit: consume the limit concurrently.

---

## Cache Poisoning

Covered in depth in `vulnerabilities/cache_poisoning.md`. The disclosed-report
lesson: **the proof is a second, unauthenticated fetch showing attacker content.**
Poisoning your own session proves nothing.

---

## The meta-pattern across all classes

Three habits account for most accepted reports:

1. **Test the fix, not the feature.** The developer patched one path. Find the
   sibling.
2. **Prove impact, not presence.** "The endpoint returns 200" is not a finding.
   "The endpoint returned user B's record to user A" is.
3. **Save the exchange.** Every accepted report in this sample shows the request
   and the response. The evidence bundle exists so that is automatic.

## What gets rejected across all classes

| Reason | Share of rejections |
|---|---|
| No impact demonstrated | most common by far |
| Out of scope (host, impact type, program rule) | very common |
| Duplicate | common |
| Theoretical / scanner output | common |
| Self-XSS, missing headers, SPF/DMARC, TLS config | program-specific, near-universal |
| Testing without authorization on third-party assets | instant ban risk |

## Sources

- HackerOne hacktivity and top-reports by bug type
- chs.us IDOR guide (practitioner reference, updated 2026)
- Intigriti "Complete Guide" series
- HackerOne disclosed reports cited inline above
