---
name: version_hunting
description: Tech-stack detection, version pinning and CVE triage — turning a fingerprint into a prioritised queue of exploitable versions.
template: jinja
---

# Version-Level Hunting

The 1-day workflow, end to end. Two tools do the mechanical work; this is when
and how to call them, and what the output does and does not mean.

```
tech_detect ──► cve_queue ──► read the advisory ──► PoC ──► prove
    │               │                │
 fingerprint    prioritised      preconditions
 + versions      CVE list          must be met
```

## 1. Fingerprint with `tech_detect`

Give it the response headers and body you already have:

```
tech_detect(
  headers_json='{"server":"nginx/1.18.0","x-powered-by":"PHP/7.4.3","set-cookie":"PHPSESSID=x"}',
  body='<meta name="generator" content="WordPress 6.4.2">'
)
```

It returns components with a confidence and, where the target disclosed one, a
version plus the signal it came from. Components are remembered for the scan.

**Read the confidence.** Two independent signals is what makes a claim strong —
WordPress at 1.00 came from a generator tag *and* a cookie. A lone
`Server: nginx` header is 0.90 for the product but tells you nothing about the
version being current. Do not treat a low-confidence match as a stack.

**Product is not version.** "They run WordPress" is worth a probe for the
version; "they run WordPress 6.4.2" is worth a CVE lookup. The output keeps
them separate because the follow-up differs.

## 2. Hunt the version when it is missing

The detector reports what it found; a missing version is your next question, not
a dead end:

- `/CHANGELOG.md`, `/CHANGELOG.txt`, `changelog.html` on the origin
- `/wp-includes/version.php`, `/readme.html` (WordPress)
- `composer.lock`, `package-lock.json`, `yarn.lock` if shipped
- `/server-status`, `?phpinfo=1`, actuator endpoints
- versioned static assets — fetch the asset and read its header comment, do
  **not** trust a `?ver=` query string alone
- behaviour: a feature present only in certain releases

Record where the version came from. "From a cached asset" and "from a live
changelog" are different claims.

## 3. Queue with `cve_queue`

```
cve_queue()                    # uses everything tech_detect remembered
cve_queue(components_json='[{"product":"nginx","version":"1.18.0"}]')
```

Ordered by what is worth trying first: KEV (known exploited in the wild), then
whether a public PoC exists, then EPSS, then CVSS. A medium with a public
exploit outranks a critical with neither.

## 4. What the queue does not tell you

**A version match is not a finding.**

`cve_queue` returns hypotheses. Two fields decide whether a hypothesis is worth
a turn:

- **`range_claimed`** — false means the affected range could not be checked
  from the feed. That means *unconfirmed*, never *not affected*. vulnx returns
  no structured range; the constraints are prose inside the description
  ("before 1.23.2, 1.22.1"). Read the advisory.
- **`preconditions`** — what must be true on the target before a PoC can fire:
  debug endpoint exposed, WebDAV enabled, a deserialization sink that accepts
  input, the component actually loaded. Most false 1-days die here, not at the
  version check.

For each candidate, answer before testing:

1. Is the discovered version inside the affected range, as the advisory states it?
2. Is the vulnerable component deployed and enabled?
3. Can you meet the auth precondition?
4. Does the public PoC require something you do not have (a debug port, a
   specific config)?

"Vulnerable version present" with those four unanswered is a scanner output, and
programs reject scanner output.

## 5. Prove it

Once a candidate survives the preconditions, follow
`exploitation/version_1day` for PoC adaptation and
`exploitation/product_exploits` for the proof standard per class. The short
version:

| Claim | Evidence |
|---|---|
| version present | the artifact you read it from, fetched live |
| vulnerable to CVE-X | the advisory range + the precondition confirmed |
| exploitable | the PoC's effect, not its exit code — a canary, a callback, a file |

## Anti-patterns

- Treating a version from a cache or a `?ver=` string as current
- Reporting a CVE whose precondition is a debug endpoint that returns 403
- Reading a nuclei template match as a finding — templates fire on version
  alone
- Calling `cve_queue` without running `tech_detect` first, then wondering why
  it is empty
