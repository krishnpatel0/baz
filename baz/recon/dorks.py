"""Search-dork arsenal — structured recon queries for agents to run.

The skill (`skills/reconnaissance/search_dorks.md`) is the human-readable
theory; this module is the machine-usable corpus. The split is the same as the
payload arsenal: prose teaches *why*, data answers *what do I run right now*.

What "useful" means here, concretely. A dork earns its place if, on a realistic
target, it returns one of:

- a credential or key that becomes an access primitive
- an exposed storage location (bucket, blob, directory listing)
- an admin or debug surface the crawler would not have found
- a host or endpoint the agent did not already know about

A dork that mostly returns marketing pages or news is excluded no matter how
often it appears in dork lists — an agent burning turns triaging noise is the
failure mode this arsenal exists to prevent.

Every query carries the phase it belongs to, so a caller can ask "what do I run
during recon phase 1" and get an ordered, deduplicated set rather than the union
of everything ever written.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


logger = logging.getLogger(__name__)


class Phase(StrEnum):
    """Recon phase ordering: cheapest and highest-value first."""

    SECRETS = "secrets"
    STORAGE = "storage"
    PANELS = "panels"
    SURFACE = "surface"
    TECH = "tech"
    ERRORS = "errors"


class Value(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True, slots=True)
class Dork:
    """One query, what it is for, and what a hit is worth."""

    id: str
    query: str
    phase: Phase
    value: Value
    description: str
    """What a hit means, in one line."""

    action: str = ""
    """What to do when it hits — the next move, not a restatement."""

    engine: str = "google"
    hits_secret: bool = False
    """Whether a hit typically yields credentials or keys."""

    tags: tuple[str, ...] = ()

    def render(self, **tokens: str) -> str:
        """Substitute ``{domain}``-style tokens; unknown tokens pass through."""
        out = self.query
        for key, value in tokens.items():
            out = out.replace("{" + key + "}", value)
        return out

    def to_wire(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "query": self.query,
            "phase": str(self.phase),
            "value": str(self.value),
            "description": self.description,
            "action": self.action,
            "engine": self.engine,
            "hits_secret": self.hits_secret,
            "tags": list(self.tags),
        }


# --- the arsenal ------------------------------------------------------------
# Kept as one tuple so ordering is meaningful: within a phase, higher value
# first. Callers should not need to re-sort.

_DORKS: tuple[Dork, ...] = (
    # --- secrets: highest value per query -----------------------------------
    Dork("s-env", "site:{domain} filetype:env", Phase.SECRETS, Value.HIGH,
         "Laravel/Node env files with credentials", "Fetch and diff for DB creds, keys",
         hits_secret=True, tags=("env", "config")),
    Dork("s-sql-dump", "site:{domain} filetype:sql", Phase.SECRETS, Value.HIGH,
         "Database dumps", "Sample records; verify the dump is current",
         hits_secret=True, tags=("database",)),
    Dork("s-log", "site:{domain} filetype:log", Phase.SECRETS, Value.HIGH,
         "Application logs", "Grep for stack traces, queries, tokens",
         tags=("logs",)),
    Dork("s-bak", "site:{domain} (filetype:bak OR filetype:old OR filetype:swp)",
         Phase.SECRETS, Value.HIGH,
         "Editor/source backups", "Diff against live source for removed secrets",
         tags=("backup",)),
    Dork("s-index-env", 'site:{domain} intitle:"index of" ".env"',
         Phase.SECRETS, Value.HIGH, "Listed env files", "Direct fetch",
         hits_secret=True, tags=("env", "listing")),
    Dork("s-index-keys", 'site:{domain} intitle:"index of" ("id_rsa" OR "id_ed25519")',
         Phase.SECRETS, Value.HIGH, "SSH private keys", "Treat as immediate access",
         hits_secret=True, tags=("ssh", "keys")),
    Dork("s-aws-keys", 'site:{domain} "AWS_ACCESS_KEY_ID" OR "AWS_SECRET_ACCESS_KEY"',
         Phase.SECRETS, Value.HIGH, "Hardcoded AWS credentials", "Validate, then scope to S3/EC2",
         hits_secret=True, tags=("aws", "keys")),
    Dork("s-jdbc", 'site:{domain} "jdbc:mysql" OR "jdbc:postgresql" OR "jdbc:mssql"',
         Phase.SECRETS, Value.HIGH, "Connection strings", "Extract host/user/pass",
         hits_secret=True, tags=("database",)),
    Dork("s-api-keys", 'site:{domain} ("api_key" OR "apikey" OR "api-key") filetype:json',
         Phase.SECRETS, Value.HIGH, "Client-side key leakage", "Check key restrictions",
         hits_secret=True, tags=("api", "keys")),
    Dork("gh-aws", 'site:github.com "{domain}" "AKIA"', Phase.SECRETS, Value.HIGH,
         "AWS keys in code", "Confirm not a test key; scope the key's permissions",
         hits_secret=True, tags=("github", "aws")),
    Dork("gh-keys", 'site:github.com "{domain}" ("sk_live_" OR "AIza" OR "xoxb-" OR "ghp_")',
         Phase.SECRETS, Value.HIGH, "Live third-party keys", "Identify service from prefix",
         hits_secret=True, tags=("github", "keys")),
    Dork("gh-rsa", 'site:github.com "{domain}" "BEGIN RSA PRIVATE KEY"',
         Phase.SECRETS, Value.HIGH, "Private keys in repos", "Decrypt what they protect",
         hits_secret=True, tags=("github", "keys")),
    Dork("pastebin", 'site:pastebin.com "{domain}"', Phase.SECRETS, Value.MEDIUM,
         "Pasted dumps", "Correlate with breach data", tags=("paste",)),
    Dork("s-db-yml", 'site:{domain} intitle:"index of" "database.yml"',
         Phase.SECRETS, Value.MEDIUM, "Rails DB config", "Fetch and extract",
         hits_secret=True, tags=("rails", "config")),
    Dork("s-password", 'site:{domain} "password" filetype:txt', Phase.SECRETS, Value.MEDIUM,
         "Plaintext password files", "Verify against live login", hits_secret=True,
         tags=("passwords",)),

    # --- storage: buckets and blob stores -----------------------------------
    Dork("s3-brand", 'site:s3.amazonaws.com "{brand}"', Phase.STORAGE, Value.HIGH,
         "S3 buckets named for the brand", "Test anonymous listing, then key read",
         tags=("s3", "aws"),
         ),
    Dork("s3-domain", 'site:s3.amazonaws.com "{domain}"', Phase.STORAGE, Value.HIGH,
         "S3 buckets named for the domain", "Same as s3-brand", tags=("s3", "aws")),
    Dork("azure", 'site:blob.core.windows.net "{brand}"', Phase.STORAGE, Value.HIGH,
         "Azure blob containers", "Test anonymous listing via ?restype=container&comp=list",
         tags=("azure", "storage")),
    Dork("gcs", 'site:storage.googleapis.com "{brand}"', Phase.STORAGE, Value.HIGH,
         "GCS buckets", "Test listing; check uniform bucket-level access",
         tags=("gcp", "storage")),
    Dork("do-spaces", 'site:digitaloceanspaces.com "{brand}"', Phase.STORAGE, Value.MEDIUM,
         "DO Spaces", "S3-compatible; same listing checks", tags=("storage",)),
    Dork("s3-logs", 'site:amazonaws.com "{domain}" filetype:log', Phase.STORAGE, Value.MEDIUM,
         "Log buckets", "Logs often contain credentials and internal hosts",
         hits_secret=True, tags=("s3", "logs")),

    # --- panels and debug surfaces -------------------------------------------
    Dork("p-admin", "site:{domain} inurl:admin", Phase.PANELS, Value.MEDIUM,
         "Admin paths", "Check auth boundary; look for default creds", tags=("admin",)),
    Dork("p-login", "site:{domain} inurl:login", Phase.PANELS, Value.MEDIUM,
         "Login surfaces", "Map auth endpoints for the auth-boundary matrix",
         tags=("auth",)),
    Dork("p-dashboard", 'site:{domain} intitle:"dashboard" OR intitle:"admin panel"',
         Phase.PANELS, Value.HIGH, "Untitle-checked panels", "Check for auth bypass",
         tags=("admin",)),
    Dork("p-grafana", 'intitle:"Grafana" site:{domain}', Phase.PANELS, Value.HIGH,
         "Grafana", "Anonymous access is a finding; dashboards leak infra detail",
         tags=("grafana", "monitoring")),
    Dork("p-jenkins", 'intitle:"Jenkins" site:{domain}', Phase.PANELS, Value.HIGH,
         "Jenkins", "Unauthenticated script console is RCE", tags=("ci", "rce")),
    Dork("p-kibana", 'intitle:"Kibana" site:{domain}', Phase.PANELS, Value.HIGH,
         "Kibana", "Logs and index data exposure", tags=("elk", "monitoring")),
    Dork("p-swagger", '(inurl:"swagger" OR inurl:"api-docs") site:{domain}',
         Phase.PANELS, Value.HIGH, "API docs", "Enumerate the full API from the spec",
         tags=("api", "docs")),
    Dork("p-graphql", "inurl:graphiql site:{domain}", Phase.PANELS, Value.HIGH,
         "GraphiQL IDE", "Introspection query, then authz matrix",
         tags=("graphql", "api")),
    Dork("p-phpmyadmin", 'intitle:"phpMyAdmin" site:{domain}', Phase.PANELS, Value.HIGH,
         "phpMyAdmin", "Default/weak creds; direct DB access",
         hits_secret=True, tags=("database", "admin")),
    Dork("p-tomcat", 'inurl:":8080" site:{domain} (intitle:"tomcat" OR inurl:"/manager/html")',
         Phase.PANELS, Value.MEDIUM, "Tomcat manager", "Default creds; WAR deploy is RCE",
         tags=("tomcat", "rce")),

    # --- surface expansion ---------------------------------------------------
    Dork("sf-files",
         "site:{domain} (filetype:xml OR filetype:conf OR filetype:ini OR filetype:yaml)",
         Phase.SURFACE, Value.MEDIUM, "Config files", "Parse for endpoints and creds",
         hits_secret=True, tags=("config",)),
    Dork("sf-docs", 'site:{domain} (filetype:pdf OR filetype:xlsx OR filetype:docx) "confidential"',
         Phase.SURFACE, Value.MEDIUM, "Internal documents", "Metadata and content review",
         tags=("documents",)),
    Dork("sf-wellknown", "site:{domain} inurl:/.well-known/", Phase.SURFACE, Value.LOW,
         ".well-known", "security.txt, ACME, webfinger", tags=("meta",)),
    Dork("sf-params",
         'site:{domain} inurl:("?id=" OR "?file=" OR "?url=" OR "?redirect=" OR "?next=")',
         Phase.SURFACE, Value.MEDIUM, "Parameterised URLs", "Seed the fuzz target list",
         tags=("params", "fuzz")),
    Dork("sf-js-config", 'site:{domain} ext:js "firebaseConfig"', Phase.SURFACE, Value.MEDIUM,
         "Firebase config in JS", "Test open rules on the referenced project",
         hits_secret=True, tags=("firebase", "js")),
    Dork("sf-archive", "site:web.archive.org {domain}", Phase.SURFACE, Value.MEDIUM,
         "Historical content", "Old endpoints still live are the best targets",
         tags=("archive", "history")),
    Dork("sf-subdomains", "site:*.example.com -site:www.example.com", Phase.SURFACE,
         Value.MEDIUM, "Non-WWW hosts", "Cross-check against crt.sh results",
         tags=("subdomains",)),

    # --- technology fingerprinting -------------------------------------------
    Dork("t-powered", 'site:{domain} "powered by"', Phase.TECH, Value.LOW,
         "Framework hints", "Correlate with 1-day engine lookups", tags=("fingerprint",)),
    Dork("t-vendor", 'site:{domain} inurl:"/vendor/"', Phase.TECH, Value.LOW,
         "Composer packages", "Versioned packages → CVE pipeline", tags=("composer",)),
    Dork("t-node", 'site:{domain} inurl:"/node_modules/"', Phase.TECH, Value.LOW,
         "Shipped node_modules", "retire/eslint against the lockfile", tags=("node",)),
    Dork("t-drupal", 'site:{domain} inurl:"/sites/default/"', Phase.TECH, Value.LOW,
         "Drupal fingerprint", "Version from CHANGELOG", tags=("cms", "drupal")),
    Dork("t-wp", "site:{domain} inurl:/wp-content/", Phase.TECH, Value.LOW,
         "WordPress", "wpscan-class enumeration is the follow-up", tags=("cms", "wordpress")),

    # --- error leaks -----------------------------------------------------------
    Dork("e-mysql", 'site:{domain} ("Warning: mysql" OR "Warning: mysqli")', Phase.ERRORS,
         Value.HIGH, "MySQL errors", "Error-based SQLi oracle", tags=("sqli", "errors")),
    Dork("e-php", 'site:{domain} "Fatal error" OR "Parse error"', Phase.ERRORS, Value.MEDIUM,
         "PHP errors", "Paths, versions, partial source", tags=("php", "errors")),
    Dork("e-stack", 'site:{domain} "Stack Trace"', Phase.ERRORS, Value.MEDIUM,
         "Stack traces", "Internal paths, framework versions", tags=("errors",)),
    Dork("e-ora", 'site:{domain} "ORA-"', Phase.ERRORS, Value.MEDIUM,
         "Oracle errors", "SQLi oracle for Oracle backends", tags=("sqli", "errors")),
    Dork("e-mssql", 'site:{domain} "Microsoft OLE DB"', Phase.ERRORS, Value.MEDIUM,
         "MSSQL errors", "SQLi oracle for MSSQL", tags=("sqli", "errors")),
)


_TOKEN_RE = re.compile(r"\{(\w+)\}")


def _supported_tokens(query: str) -> set[str]:
    return set(_TOKEN_RE.findall(query))


def all_dorks() -> tuple[Dork, ...]:
    return _DORKS


def by_phase(phase: str | Phase) -> tuple[Dork, ...]:
    """Dorks for one phase, value-ordered."""
    want = str(phase).lower()
    return tuple(d for d in _DORKS if d.phase.value == want)


def search(
    *,
    phase: str | None = None,
    min_value: str | None = None,
    tags: list[str] | None = None,
    hits_secret: bool | None = None,
    limit: int | None = None,
) -> list[Dork]:
    """Filter the arsenal; value is a floor, tags are an AND."""
    floor = Value(min_value).value if min_value else None
    order = {Value.HIGH: 0, Value.MEDIUM: 1, Value.LOW: 2}

    out: list[Dork] = []
    for dork in _DORKS:
        if phase and dork.phase.value != phase:
            continue
        if floor and order[dork.value] > order[Value(floor)]:
            continue
        if tags and not all(t in dork.tags for t in tags):
            continue
        if hits_secret is not None and dork.hits_secret is not hits_secret:
            continue
        out.append(dork)
        if limit and len(out) >= limit:
            break
    return out


def plan_for(**tokens: str) -> list[dict[str, Any]]:
    """A ready-to-run plan: every dork, ordered by phase then value, rendered.

    Unknown tokens stay as placeholders so the caller can see what is missing
    rather than silently running a half-rendered query.
    """
    plan: list[dict[str, Any]] = []
    for dork in _DORKS:
        missing = _supported_tokens(dork.query) - set(tokens)
        plan.append(
            {
                **dork.to_wire(),
                "rendered": dork.render(**tokens),
                "missing_tokens": sorted(missing),
            }
        )
    return plan
