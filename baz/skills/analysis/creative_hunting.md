# Creative Hunting — Beyond the Textbook

> This skill exists for the bugs that have no class name yet. The other skills
> teach what is known; this one teaches how to look for what is not.
>
> Textbook testing finds textbook bugs. The findings that pay well and are not
> duplicates come from noticing something the checklist does not cover — a state
> the developers did not consider, a trust relationship nobody reviewed, a
> feature used in a way its author never imagined.

## The habits that find novel bugs

### 1. Ask "what does the developer *assume*?"

Every bug is an assumption that turned out to be false. Hunt the assumptions,
not the code:

| Assumption | How to test it |
|---|---|
| "This endpoint is only called by our frontend" | call it directly, with odd parameters |
| "Users will only upload images" | send a polyglot, an SVG with scripts, a zip bomb, a 0-byte file |
| "IDs are unguessable" | where else do they leak? (emails, share links, other endpoints) |
| "This field is read-only" | include it in a PUT/PATCH body |
| "The mobile app is the only API consumer" | is there a `/api/v1/` the webapp abandoned? |
| "Nobody will have two accounts" | register twice, compare everything |
| "Rate limiting protects this" | is the limit per-IP, per-account, per-session? bypassable via headers? |
| "The admin panel is not linked" | find it, then test it unauthenticated |
| "This value comes from the server" | can the client set it? (price, role, tenant) |
| "Errors never contain data" | trigger every error path deliberately |

### 2. Follow the data, not the feature

Pick one piece of data — an email address, a file, a price — and follow it
through the entire application:

- Where is it entered?
- Where is it stored? (raw, encoded, sanitized?)
- Where is it displayed? (which context? whose session?)
- Where is it exported? (PDF, CSV, email — new rendering context)
- Where is it deleted? (does deletion actually reach every copy?)
- What happens to *references* to it after deletion?

Bugs live in the transitions: stored-as-X-rendered-as-Y, exported-to-a-new-context,
deleted-but-referenced.

### 3. Compare states

The most reliable novel-bug technique: run the same request under two conditions
and diff everything — status, headers, body, timing, side effects.

- Same request as user A vs user B
- Same request authenticated vs not (some responses differ in *leakage*, not access)
- Same flow on web vs mobile API vs old API version
- Same action before vs after some state change (email verified, subscription expired)
- Same request twice in a row (idempotency assumptions)

### 4. Abuse the features nobody abuses

High-value targets that get little testing:

| Feature | Novel angle |
|---|---|
| PDF/report generation | SSRF via image/link fetch, HTML injection into the rendered doc, formula injection in CSV exports |
| Webhooks | SSRF (target internal), replay, signature confusion, registering `http://169.254.169.254/` |
| Import/export | XML entity injection (xlsx is a zip of XML), CSV formula injection, zip-slip on extract |
| Integrations (Slack/Google/GitHub) | OAuth scope confusion, webhook URL takeover, token leakage in logs |
| Password reset "link by email" | email enumeration, token in referrer, HTML injection into the email |
| Multi-tenancy | tenant ID in the *body* of a path-keyed endpoint, tenant switch without re-auth |
| Sharing/collaboration | permission inheritance bugs, share-link revocation failures, ACL on nested objects |
| Search | injection into the search backend, result-based blind extraction |
| Notifications | injection into push/email templates, subscription to other users' events |
| Billing | currency round-trip, negative quantities, trial extension via timezone |

### 5. Think in object graphs

Not "can I read object 5?" but "what does object 5 *reference*?"

```
Order ──► User ──► Tenant ──► Settings
   │
   └──► Invoice ──► PaymentMethod
```

Authorization is usually enforced at the first hop. Ask: from an object I can
read, what can I reach *through* it? `GET /orders/5` may be checked; the
`payment_method_id` inside it may not be, on the endpoint that fetches payment
methods by ID.

### 6. Question the trust boundaries nobody drew

- **Server-to-server**: does the app trust headers from its own microservices?
  Can you reach an internal service that trusts `X-Internal-User`?
- **Build/deploy**: are `.map` files, `.git`, `.env` on the origin because a
  build step leaked them?
- **Email as a trust boundary**: does the app trust the `Reply-To` or links in
  an email the user can influence?
- **Browser cache / bfcache**: does an authenticated page survive logout in
  back/forward cache?
- **Subdomains**: can a subdomain you can take over set cookies for the parent
  domain, or receive its CSP violations?

### 7. Replay with a different audience

Change who *receives* the effect:

- Trigger an email/SMS/webhook to an address you control, but with content meant
  for someone else
- Change the `lang`/locale and see if error handling diverges
- Change the client (`User-Agent`, `Accept`) — mobile endpoints are often
  less guarded

## The out-of-the-box loop

```
1. Read the feature list as an attacker: which one moves money/identity/data?
2. For that feature: what does the developer assume about its input?
3. Violate exactly one assumption, precisely.
4. Diff the outcome against the honest request.
5. If the diff is interesting: chain it. If not: log it and move on.
6. Everything through the proxy; every hit into the evidence bundle.
```

## Mindset

- The checklist finds the bugs the checklist covers. Everything else requires
  asking what the author assumed.
- Most novel findings are *old bugs in new places* — an IDOR on a brand-new
  endpoint, a sanitizer bypass on a newly added field, an auth gap on the mobile
  API. New features are under-tested by definition.
- A bug you cannot chain or demonstrate is still worth recording in notes with
  `open_proof_gap` — future findings may complete it.
- If the app feels boring, you are looking at the surface. Pick a data type and
  follow it.
