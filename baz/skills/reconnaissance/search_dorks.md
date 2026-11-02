# Dork Arsenal — Recon Phase

> Curated search-engine queries for offensive recon. Grouped by what the answer
> unlocks, not by engine. Each entry states what it finds and what it's worth —
> a dork that returns noise is worse than no dork, because an agent burns turns
> triaging it.

## Call the tool, do not paste queries

`dork_search(domain=..., phase=..., min_value="high", brand=..., keywords=...)`
returns the queries below already rendered for your target, ordered, each with
what a hit means and the next action. **Use it instead of composing queries by
hand** — it drops queries whose tokens you have not supplied rather than
returning them half-rendered, and it orders by value so you spend turns on
`filetype:env` before `inurl:/wp-content/`.

`dork_stats()` shows the arsenal size and phase distribution if you need to
know what is available.

Then run the returned queries with `web_search`. A hit on a secrets dork is an
access primitive — pivot to it immediately rather than continuing recon.

## How agents use this

Dorks are **passive recon**: no packet touches the target. They surface third
parties' records *about* the target — leaked configs, exposed buckets, cached
admin panels, forgotten subdomains. That makes them safe to run against any
target, early, before anything noisy.

Run order within a phase: credentials/secrets first (highest value per query),
then exposure (buckets, panels), then attack surface expansion (subdomains,
endpoints), then technology. A hit in the first group reshapes the whole
engagement.

## Substitution tokens

| Token | Meaning |
|---|---|
| `{domain}` | target apex, e.g. `example.com` |
| `{subdomain}` | a discovered host, e.g. `staging.example.com` |
| `{brand}` | company name, no TLD |
| `{keywords}` | product + technology words, e.g. `invoice api` |

---

## 1. Credentials, tokens and secrets

The highest-value group. A hit here usually means immediate access.

### Google

```
site:{domain} filetype:env
site:{domain} filetype:sql
site:{domain} filetype:log
site:{domain} filetype:bak OR filetype:old
site:{domain} intitle:"index of" ".env"
site:{domain} intitle:"index of" "id_rsa"
site:{domain} intitle:"index of" "database.yml"
site:{domain} "password" filetype:txt
site:{domain} "api_key" OR "apikey" OR "api-key" filetype:json
site:{domain} "jdbc:mysql" OR "jdbc:postgresql"
site:{domain} intext:"AWS_ACCESS_KEY_ID" OR intext:"AWS_SECRET_ACCESS_KEY"
site:pastebin.com "{domain}" password
site:github.com "{domain}" "AKIA"            # AWS access key prefix
site:github.com "{domain}" "BEGIN RSA PRIVATE KEY"
site:github.com "{domain}" "smtp" password
site:gitlab.com "{domain}" token
site:gist.github.com "{domain}"
"copyright {brand}" "mysql_connect" OR "mysqli_connect"
```

### GitHub code search (needs login; queries still valid)

```
"{domain}" filename:.env
"{domain}" filename:.npmrc _auth
"{domain}" filename:secrets.tf
"{domain}" filename:.git-credentials
"{domain}" "sk_live_"                        # Stripe live keys
"{domain}" "AIza"                            # Google API key prefix
"{domain}" "xoxb-" OR "xoxp-"                # Slack tokens
"{domain}" "ghp_" OR "gho_"                  # GitHub tokens
org:{brand} filename:config.php DB_PASSWORD
```

### exposed directories

```
intitle:"index of" site:{domain}
intitle:"Index of /admin"
intitle:"index of" "backup"
intitle:"index of" ".git"
intitle:"index of" "wallet.dat"
```

**What to do with a hit:** capture the URL, fetch the artifact *through the
sandbox proxy* so it's recorded, and treat the credential as a primitive for the
chain composer — a leaked SMTP password is a phishing primitive; a leaked AWS key
is an S3 primitive and possibly a compute primitive.

---

## 2. Cloud storage exposure

Buckets and blob stores are the most common real-world data leak.

### S3

```
site:s3.amazonaws.com "{brand}"
site:s3.amazonaws.com "{domain}"
inurl:s3.amazonaws.com "{keywords}"
site:s3.amazonaws.com intitle:"index of" "{brand}"
inurl:s3-us-west-2.amazonaws.com "{brand}"
site:amazonaws.com "{domain}" filetype:log
```

### Azure / GCP / generic

```
site:blob.core.windows.net "{brand}"
site:*.blob.core.windows.net "{domain}"
site:storage.googleapis.com "{brand}"
site:storage.googleapis.com "{keywords}"
inurl:storage.googleapis.com/static
site:digitaloceanspaces.com "{brand}"
site:cdn.digitaloceanspaces.com "{keywords}"
```

### Bucket name brute force (active, engine-free)

Naming follows patterns; the arsenal enumerates them against DNS + HTTP:

```
{brand}-assets     {brand}-backup     {brand}-backups
{brand}-dev        {brand}-staging    {brand}-prod
{brand}-production {brand}-uploads    {brand}-static
{brand}-media      {brand}-data       {brand}-logs
{brand}-documents  {brand}-files      {brand}-images
{brand}-public     {brand}-private    {brand}-internal
{brand}-{region}   {brand}-eu         {brand}-us
backup-{brand}     assets-{brand}     static-{brand}
```

**Assessment rule:** a bucket that returns `ListBucketResult` for `?list-type=2`
is a finding — enumerate keys, sample records, save impact artifacts. A bucket
that returns `AccessDenied` for listing but serves a known key directly is
*also* a finding (unauthenticated object read) — try the object paths seen in the
target's HTML/JS.

---

## 3. Admin panels and login surfaces

### Google

```
site:{domain} inurl:admin
site:{domain} inurl:login
site:{domain} intitle:"admin panel"
site:{domain} intitle:"dashboard"
site:{domain} inurl:/wp-admin
site:{domain} inurl:/administrator      # Joomla
site:{domain} inurl:/admin/login
inurl:admin site:{subdomain}
site:{domain} inurl:"/admin/config"
```

### Panels by product

```
intitle:"Grafana" site:{domain}
intitle:"Kibana" site:{domain}
intitle:"Jenkins" site:{domain}
intitle:"GitLab" site:{domain}
inurl:":8080" site:{domain} intitle:"tomcat"
intitle:"phpMyAdmin" site:{domain}
inurl:/jmx-console/ site:{domain}
intitle:"swagger" OR inurl:/swagger-ui site:{domain}
inurl:/graphiql site:{domain}
```

---

## 4. Attack surface expansion

### Subdomains and forgotten hosts

```
site:*.example.com -site:www.example.com
site:{domain} -www -mail
"view the pom.xml" OR "view the build.gradle"   # rarely; skip
site:{subdomain} -inurl:www
```

### Files worth reading

```
site:{domain} filetype:xml
site:{domain} filetype:conf
site:{domain} filetype:cfg
site:{domain} filetype:ini
site:{domain} filetype:yml OR filetype:yaml
site:{domain} filetype:pdf "confidential"
site:{domain} filetype:xlsx "internal"
site:{domain} ext:action OR ext:do                 # Struts
site:{domain} inurl:/.well-known/
site:{domain} inurl:swagger.json
site:{domain} inurl:api-docs
```

### Cached / historical content

```
cache:{domain}/admin
site:web.archive.org {domain}
```

### exposed parameters worth fuzzing

```
site:{domain} inurl:"?id="
site:{domain} inurl:"?file="
site:{domain} inurl:"?redirect="
site:{domain} inurl:"?url="
site:{domain} inurl:"?next="
site:{domain} inurl:"?return="
site:{domain} inurl:"?page="
```

---

## 5. People and technology

```
site:{domain} intitle:"@gmail" OR "@outlook"     # mails in the open
site:{domain} "mailto:"
intext:"{brand}" "@{domain}"
site:linkedin.com/in "{brand}" engineer
```

### Technology fingerprinting via dorks

```
site:{domain} "powered by"
inurl:"/wp-content/" site:{domain}
inurl:"/sites/default/" site:{domain}            # Drupal
inurl:"/sites/all/" site:{domain}
site:{domain} inurl:"/vendor/"                   # composer
inurl:"/node_modules/" site:{domain}
site:{domain} ext:js "firebaseConfig"
```

---

## 6. Error pages that leak

```
site:{domain} "Warning: mysql"
site:{domain} "Warning: mysqli"
site:{domain} "Fatal error"
site:{domain} "Microsoft OLE DB"
site:{domain} "ORA-" OR "ORA-00"
site:{domain} "PostgreSQL query failed"
site:{domain} "syntax error" filetype:log
site:{domain} "Stack Trace"
site:{domain} intitle:"Error" "at line"
```

---

## Engine notes

| Engine | Strengths | Limits |
|---|---|---|
| Google | broadest index, best for `filetype:` and `intitle:` | rate limits hard, blocks automation |
| Bing | more forgiving, good `inurl:` support | smaller index |
| DuckDuckGo | `!g` / `!b` bangs to other engines; anonymous | no operator depth of its own |
| GitHub search | the single best source of leaked secrets | login required for code search |
| crt.sh | every cert ever logged — passive subdomain enum, no rate limit | no content |
| Shodan | open ports, banners, exposed services | API key for depth |
| Wayback | removed-but-cached content, old endpoints | no secrets, historical only |
| theHarvester | emails + hosts from many sources at once | noisier |

---

## Discipline

1. **Dorks are recon, not testing.** Never fuzz through a search engine; never
   run active enumeration queries (`inurl:"?id="` then fuzz) against a target
   before checking scope.
2. **Record the query, not just the hit.** `dork.json` stores every query with
   its hit count and top URLs, so results are reproducible and the report can
   say how the surface was found.
3. **Cache politely.** The same dork against the same domain inside 24h should
   read from the local store, not re-query.
4. **Scope check before active follow-up.** A dork hit on
   `staging.{domain}` is *still in scope* if `{domain}` is; a hit on
   `acme-partner.com` is not, no matter how interesting.
