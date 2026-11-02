# GraphQL Security

> GraphQL gives attackers a query language. The endpoint is one URL; the attack
> surface is the entire schema. The work is introspection → authorization matrix
> → batching/depth abuse → injection via variables.

## Recon

```bash
# endpoint discovery
ffuf -w /opt/wordlists/discovery/graphql.txt -u https://target/FUZZ -mc 200,400
# common paths: /graphql, /graphiql, /api/graphql, /graphql/v1, /v1/graphql,
#               /api/graph, /altair, /playground
```

**Introspection first** — the full schema is the endpoint map:

```graphql
{ __schema { types { name fields { name type { name kind } } } } }
```

If introspection is blocked (many programs do), recover the schema anyway:

| Technique | How |
|---|---|
| field suggestion oracle | misspell a field: `"Did you mean 'orders'?"` leaks the schema one suggestion at a time |
| GET-based introspection | `?query={__schema{...}}` when POST is blocked |
| Apollo tracing / playground artifacts | `/graphql` with `Accept: application/json` + `X-Apollo-Tracing: 1` |
| client-side persisted queries | extract from shipped JS bundles |

`clairvoyance` automates the suggestion-oracle recovery.

## Authorization testing

GraphQL authorization failures are field-level, not endpoint-level — the matrix
from `api_authz_matrices.md` applies per *field*.

| Vector | Test |
|---|---|
| object-level (BOLA) | `user(id: <other-id>) { email }` as role B |
| field-level | role B queries `me { passwordHash }` — filtered or served? |
| mutation-level | `deleteUser(id:)` as role B |
| depth bypass | `user { orders { user { orders { ... } } } }` — object checks on the first hop only |
| alias batching | `query { a: user(id:1){email} b: user(id:2){email} }` — N queries in one |
| array batching | JSON body is an array of queries — authz/rate-limit sees one |
| directive abuse | `@skip`/`@include` to vary queries under a broken parser |
| error-based | partial failures leak data before the error aborts the response |

**Aliases are the GraphQL equivalent of parameter pollution.** Rate limiting and
audit logging that count *requests* miss them.

## Injection via variables

GraphQL variables are typed; type confusion is a real injection class:

| Type confusion | Payload |
|---|---|
| array where scalar expected | `"id": ["1"]` — some ORMs build `IN (…)` clauses |
| object injection | `"filter": {"$ne": null}` — NoSQL operators straight through |
| nested JSON | `"q": {"$regex": ".*"}` |
| string to enum | `"role": "ADMIN "` (trailing space) — enum coercion bugs |

Test variables against the backing store, not the GraphQL layer: a Postgres
backend, a Mongo backend and a Dynamo backend fail differently.

## Denial of service (only where the program allows)

| Vector | Shape |
|---|---|
| deep query | 1000-level nesting |
| circular fragment | `query Q { ...Q }` fragments |
| huge alias count | thousands of aliases in one query |
| introspection depth | massive `__schema` query |

Most programs class GraphQL DoS as out of scope; demonstrate once with a
depth-limited probe and describe. Never loop it.

## Batching and rate-limit evasion

```json
[
  {"query":"mutation { login(u:\"a\",p:\"b\") { token } }"},
  {"query":"mutation { login(u:\"a\",p:\"c\") { token } }"}
]
```

Hundreds of login attempts inside one HTTP request. If the app has rate limiting
on the endpoint and not on operations, this is a credential-stuffing primitive —
and a finding about the rate limiter, not just GraphQL.

## Proof standard

| Claim | Evidence |
|---|---|
| BOLA | role B response containing another user's object fields, the query shown |
| field-level leak | `passwordHash`/`email` in role B's response |
| alias abuse | one request, N operations performed |
| introspection | the recovered schema saved as an artifact |
| batching | request JSON array + N side effects observed |

Save the **introspected schema** in the bundle — `impact/schema.graphql` — and
the exact queries used. A GraphQL finding without its queries is not
reproducible.

## Tooling

```bash
# schema recovery and testing
clairvoyance -u https://target/graphql -o schema.json
# query testing
inql                                    # Burp extension
# batch abuse
ffuf -w aliases.txt -u https://target/graphql -X POST -H 'Content-Type: application/json' -d @batch.json
```

## Anti-patterns

- "Introspection disabled" ⇒ "GraphQL secure" (field suggestions leak it anyway)
- Testing only the endpoint, not the schema's mutations
- Ignoring variables because the query "looks safe"
- Deep-query DoS as a headline finding — it is usually out of scope
