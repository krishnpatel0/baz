# Subdomain Takeover — Verification

> A dangling DNS record pointing at a claimable service is a takeover. The skill
> is *verifying claimability* — most "vulnerable" subdomains are actually
> reserved by the provider, and a false positive here is embarrassing in both
> directions.

## The chain

```
sub.example.com  ──CNAME──►  example.s3.amazonaws.com   (bucket deleted)
      │                              │
      │ DNS resolves                 │ 404 NoSuchBucket
      ▼                              ▼
   anyone can create the bucket  ──►  sub.example.com serves ATTACKER CONTENT
```

Takeover requires: the record is dangling (target gone), **and** the provider
lets a third party claim that exact resource name, **and** the provider's edge
serves it for the original hostname.

## Fingerprint table — the load-bearing part

| Service | DNS record | Dangling response | Claimable? |
|---|---|---|---|
| AWS S3 | CNAME/A → `*.s3.amazonaws.com` | `NoSuchBucket` (XML) | **yes** — recreate the bucket |
| AWS CloudFront | CNAME → `*.cloudfront.net` | `Bad request` / missing distribution | **no** — distribution IDs are account-bound |
| Azure CDN | CNAME → `*.azureedge.net` | `404 Not Found` | **no** on `*.azureedge.net` (reserved); **yes** historically on custom |
| Azure Websites | CNAME → `*.azurewebsites.net` | `404 Site Not Found` | **yes**, if custom domain not reserved |
| GitHub Pages | CNAME → `*.github.io` | `404 There isn't a GitHub Pages site here` | **yes**, if repo pages not claimed |
| Heroku | CNAME → `*.herokudns.com` | `No such app` | **yes** |
| Fastly | CNAME → `*.fastly.net` | `Fastly error: unknown domain` | **yes** |
| Surge.sh | CNAME → `*.surge.sh` | `project not found` | **yes** |
| Netlify | CNAME → `*.netlify.app` | `Not Found - Request ID` | **yes** |
| Vercel | CNAME → `*.vercel.app` / `cname.vercel-dns.com` | `DEPLOYMENT_NOT_FOUND` | **yes** |
| Bitbucket | CNAME → `*.bitbucket.io` | `Repository not found` | **yes** |
| Shopify | CNAME → `*.myshopify.com` | `Sorry, this shop is currently unavailable` | **no** — reserved |
| Tumblr | CNAME → `domains.tumblr.com` | `There's nothing here.` | **yes** |
| Zendesk | CNAME → `*.zendesk.com` | `Help Center Closed` | **yes** |
| Firebase | CNAME → `*.web.app` | `Site Not Found` | **yes** |
| Readme.io | CNAME → `custom.readme.io` | `Project doesnt exist... yet` | **yes** |
| Tilda | CNAME → `*.tildacdn.com` | `Please renew your subscription` | varies |
| Agile CRM | CNAME → `*.agilecrm.com` | `Sorry, page not found` | yes |
| Pingdom | CNAME → `stats.pingdom.com` | `pingdom`-branded 404 | no |

**The fingerprint is the response body**, not the status code. Many of these
return 404 for both claimed and unclaimed states.

## The verification procedure — in order

1. **Enumerate** — collect every subdomain (crt.sh, `subfinder`, amass, the dork
   arsenal's `sf-subdomains`).
2. **Resolve** — find records pointing at provider edges. `dig +short CNAME`.
3. **Fingerprint** — fetch `http://sub.example.com/` (both schemes); match the
   body against the table.
4. **Verify claimability** — the step everyone skips:
   - S3: `aws s3 ls s3://that-bucket` unauthenticated, or attempt a harmless
     object PUT in a *test* bucket with the same name pattern — if creation
     succeeds, the original name is claimable.
   - GitHub Pages: create a repo, add a `CNAME` file with the hostname; if Pages
     accepts and serves it, takeover is proven.
   - Azure: attempt to bind the custom domain in a test account; a reservation
     error means it is protected.
5. **Serve proof content** — a `BAZ-<token>` marker page, nothing more.
6. **Capture** — screenshot of the served marker at the victim hostname, DNS
   records, and the claim step.
7. **Report** with remediation: delete the DNS record *and* (where possible)
   re-register the resource yourself.

## Distinguish from lookalike findings

| Finding | Is it takeover? |
|---|---|
| CNAME to a provider, site works normally | no |
| NXDOMAIN on the hostname but CNAME exists | maybe — check the edge |
| Wildcard `*.azurewebsites.net` reserved by Microsoft | no — reserved names are safe |
| Deleted bucket recreated by a *third party already* | incident, not finding — report as abuse |

A wildcard reservation by the provider (e.g. `*.cloudfront.net`) is the most
common false positive.

## Tooling

```bash
# enumeration + fingerprints
subzy run --hide_fails --targets subs.txt
# or
nuclei -t takeovers/ -l subs.txt
# resolution detail
dig +short CNAME sub.example.com
dig +noall +answer sub.example.com CNAME
```

Both tools fingerprint bodies; verify manually anyway — their fingerprints lag
provider changes.

## Proof standard

| Claim | Evidence |
|---|---|
| dangling record | `dig` output showing the CNAME + provider 404 |
| claimable | the provider accepting your claim of that exact resource |
| served | screenshot of `BAZ-<token>` served at `sub.example.com` |
| scope | hostname was in the program's scope, or apex was |

The claim step is what separates a finding from a "dangling DNS" observation.

## Cleanup

Delete the claim (bucket/repo/pages site) immediately after capture and verify
the hostname stops serving your marker. Note both actions in the report.

## Anti-patterns

- Reporting every 404 as takeover — reserved domains are everywhere
- Fingerprinting from a screenshot of someone else's blog post
- Skipping the claim step because it "obviously would work"
- Leaving claimed resources live
