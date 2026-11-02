# API Authorization Matrices — BOLA/BFLA at Scale

> IDOR testing one endpoint at a time is how testers miss the actual finding. An
> authorization matrix — every endpoint × every role — is how you find the one
> endpoint the developers forgot, and *prove* it systematically.

## The model

```
              │ Role A (owner) │ Role B (other tenant) │ Anonymous
GET /orders/1 │      200       │        ???            │    ???
PUT /orders/1 │      200       │        ???            │    ???
GET /users/me │      200       │        200            │    ???
```

The `???` cells are the test. An unexpected 200 in Role B's column is a finding.
An unexpected 200 in Anonymous's column is a critical.

BOLA = object-level (can I read *that object*). BFLA = function-level (can I
*call that operation*). Both come from the same matrix.

## Building the matrix

### 1. Enumerate endpoints

From, in order of value:

- **OpenAPI/Swagger spec** — `/openapi.json`, `/swagger.json`, `/api-docs`,
  `/api/swagger`, plus the dork arsenal's `p-swagger`
- GraphQL introspection — operations and types map 1:1 to endpoints
- JS bundles — `api-calls` extraction from shipped code
- Proxy history — what the app actually calls (Caido sitemap)
- Guessing from the spec of a *previous* API version (`/v1/` vs `/v2/`)

### 2. Enumerate roles

Minimum set for any app with tenancy:

| Role | How obtained |
|---|---|
| Anonymous | no session |
| User A | registration flow |
| User B | second registration (different tenant if multi-tenant) |
| Admin | only if program provides test accounts |

**Never** brute-force or use production accounts. Two self-registered accounts
cover the BOLA surface; admin testing only with program-provided credentials.

### 3. Record object IDs

From User A's traffic: the IDs that appear in paths and bodies (`/orders/8412`,
`"account_id": "acct_9f3"`). These are the objects User B will reach for.

## Running the matrix

For each endpoint × role pair:

```python
# sketch of the sweep the agent should write
for endpoint in endpoints:
    for role in roles:
        r = session[role].request(endpoint.method, endpoint.url,
                                  json=endpoint.body_variant(role))
        matrix[endpoint][role] = (r.status_code, len(r.content), hash(r.text[:200]))
```

Signals, per cell:

| Expected | Actual | Verdict |
|---|---|---|
| 403/404 | 200 + A's data | **BOLA/BFLA** |
| 403/404 | 200 + different record | check what it returned — mass exposure |
| 401 | 200 | auth missing entirely |
| 403 | 403 but body leaks info | response-differential leak |
| 404 | 404 | correct — but compare `404 vs 403` shapes for enumeration |

**Differential details matter**: identical 403s across roles is correct;
*different* 403 bodies (or timing) can leak object existence.

## Body tampering beyond the ID

Authorization bugs hide in fields, not just paths:

| Field | Test |
|---|---|
| `"tenant_id": "t_b"` | swap tenant in the *body* on a path-keyed endpoint |
| `"user_id": 2` | mass-assignment of ownership |
| `"role": "admin"` | privilege escalation via mass assignment |
| `"price": -1`, `"qty": 0` | business logic — see `business_logic.md` |
| `"account": "acct_9f3"` | object reference in nested objects |
| HTTP method | `GET /admin/users` 403 but `HEAD`, `POST` override, or `X-HTTP-Method-Override` passes |

## GraphQL-specific

| Vector | Test |
|---|---|
| field-level authz | query `user { email }` as role B — is `email` still returned? |
| operation-level | mutations blocked at the endpoint but reachable via aliases |
| batching | `[{query1},{query2},...]` — does rate limiting / authz see one request? |
| nested queries | `user { orders { items { price } } }` — depth bypasses object checks |
| introspection as anon | full schema = endpoint map for the matrix |

## REST-specific

| Vector | Test |
|---|---|
| verb tampering | `GET` on a `POST`-guarded route |
| trailing characters | `/admin/users/` vs `/admin/users/.` vs `/admin/users;%2fadmin` |
| case | `/Admin/Users` |
| version drift | `/api/v2/orders` fixed, `/api/v1/orders` not |
| content-type confusion | `Accept: application/json` vs sending XML where both are parsed |
| mass assignment | extra fields in PUT/POST bodies |

## Chained tests

| Chain | Primitives |
|---|---|
| registration enum + matrix | find protected endpoint → confirm role B access → impact |
| IDOR on file IDs → metadata → other-user documents | read chain across object types |
| BOLA read + BOLA write | prove modification, not just viewing |

## Proof standard

| Claim | Minimum evidence |
|---|---|
| BOLA read | role B response containing **User A's object**, with the object id visible in both requests |
| BOLA write | before/after of the object, modified as role B |
| BFLA | role B successfully invoking an admin operation |
| matrix result | the rendered matrix as an artifact |

The matrix itself is evidence — `impact/authz-matrix.md` in the bundle, every
cell filled, the anomalous cells marked.

## Anti-patterns

- One-endpoint IDOR testing and declaring the API clean
- Using production accounts as role B
- Ignoring 403 body differentials
- Reporting BOLA from a 200 without showing the *other user's* data in it
- Filling the matrix from memory instead of from captured requests
