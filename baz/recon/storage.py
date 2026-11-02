"""Cloud storage enumeration — find the bucket before you find the leak.

S3/GCS/Azure buckets leak more real data than any web bug class, and they are
found by naming patterns rather than by exploitation. The value here is the
generator plus the *assessment* rules: most buckets return an error, and only
three responses matter.

The naming knowledge is the load-bearing part. Companies rarely invent bucket
names; they follow `{brand}-{purpose}-{env}-{region}` because that is what
Terraform defaults emit.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import StrEnum
from itertools import product as cartesian


logger = logging.getLogger(__name__)


PURPOSES: tuple[str, ...] = (
    "assets",
    "static",
    "media",
    "images",
    "img",
    "uploads",
    "files",
    "docs",
    "documents",
    "backup",
    "backups",
    "data",
    "logs",
    "log",
    "cache",
    "cdn",
    "public",
    "private",
    "internal",
    "dev",
    "test",
    "staging",
    "prod",
    "production",
    "archive",
    "exports",
    "reports",
    "temp",
    "tmp",
    "content",
    "storage",
    "website",
    "web",
    "app",
    "api",
    "config",
    "secrets",
    "db",
    "database",
)

ENVIRONMENTS: tuple[str, ...] = (
    "dev",
    "test",
    "staging",
    "stage",
    "prod",
    "production",
    "uat",
    "qa",
)

REGIONS: tuple[str, ...] = (
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "eu-west-1",
    "eu-west-2",
    "eu-central-1",
    "eu-north-1",
    "ap-south-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
    "sa-east-1",
    "ca-central-1",
)


class Provider(StrEnum):
    S3 = "s3"
    GCS = "gcs"
    AZURE = "azure"


class BucketState(StrEnum):
    """What the bucket told us. Only three of these are interesting."""

    PUBLIC_LIST = "public_list"
    """Listing returned objects — full enumeration possible."""
    PUBLIC_READ = "public_read"
    """Listing denied but a known object served — object-level exposure."""
    EXISTS_PRIVATE = "exists_private"
    """Exists and is properly closed. Not a finding; useful for naming."""
    REDIRECT = "redirect"
    """Wrong region — the bucket exists, retry against the right endpoint."""
    NOT_FOUND = "not_found"
    ACCESS_DENIED = "access_denied"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class BucketCandidate:
    name: str
    provider: Provider

    @property
    def list_url(self) -> str:
        if self.provider is Provider.S3:
            return f"https://{self.name}.s3.amazonaws.com/?list-type=2&max-keys=5"
        if self.provider is Provider.GCS:
            return f"https://storage.googleapis.com/storage/v1/b/{self.name}/o?maxResults=5"
        # Azure container names are not global; the storage account is.
        return f"https://{self.name}.blob.core.windows.net/?comp=list"

    @property
    def object_url_template(self) -> str:
        if self.provider is Provider.S3:
            return f"https://{self.name}.s3.amazonaws.com/{{key}}"
        if self.provider is Provider.GCS:
            return f"https://storage.googleapis.com/{self.name}/{{key}}"
        return f"https://{self.name}.blob.core.windows.net/{{container}}/{{key}}"


def generate(
    brand: str,
    *,
    providers: tuple[Provider, ...] = (Provider.S3, Provider.GCS),
    include_regions: bool = True,
    limit: int = 400,
) -> list[BucketCandidate]:
    """Generate likely bucket names for a brand.

    Ordered most-likely first: bare brand, then brand-purpose, then
    purpose-brand, then environment and region variants. A caller that stops
    early has tested the highest-probability half.

    S3 names must be DNS-safe and 3-63 chars, so generation normalises rather
    than emitting names that cannot exist.
    """
    base = _normalise(brand)
    if not base:
        return []

    names: list[str] = [base]
    names.extend(f"{base}-{p}" for p in PURPOSES)
    names.extend(f"{p}-{base}" for p in PURPOSES[:12])
    names.extend(f"{base}{p}" for p in PURPOSES[:8])

    for purpose, env in cartesian(PURPOSES[:14], ENVIRONMENTS):
        names.append(f"{base}-{purpose}-{env}")
        if len(names) >= limit:
            break

    if include_regions:
        for region in REGIONS:
            names.append(f"{base}-{region}")
            names.append(f"{base}-assets-{region}")

    # Azure storage accounts are 3-24 chars, lowercase alphanumeric only.
    azure_names = [n.replace("-", "").replace(".", "")[:24] for n in names[:60]]

    out: list[BucketCandidate] = []
    seen: set[str] = set()
    # One provider at a time, round-robin across names, so a caller's ``limit``
    # does not silently exhaust the list before reaching the last provider.
    name_list = [n for n in names if 3 <= len(n) <= 63]
    for index in range(len(name_list)):
        name = name_list[index]
        if name in seen:
            continue
        seen.add(name)
        for provider in providers:
            if provider is Provider.AZURE:
                continue
            out.append(BucketCandidate(name=name, provider=provider))
    if Provider.AZURE in providers:
        azure_seen: set[str] = set()
        for name in azure_names:
            if 3 <= len(name) <= 24 and name not in azure_seen:
                azure_seen.add(name)
                out.append(BucketCandidate(name=name, provider=Provider.AZURE))

    # Reserve a share per provider before truncating. Azure accounts are only
    # generated at the end, so a naive ``out[:limit]`` would always drop them —
    # a caller asking for N names would never test the third provider.
    if limit and len(providers) > 1:
        per_provider = max(1, limit // len(providers))
        kept: list[BucketCandidate] = []
        counts: dict[Provider, int] = {}
        for candidate in out:
            used = counts.get(candidate.provider, 0)
            if used >= per_provider:
                continue
            counts[candidate.provider] = used + 1
            kept.append(candidate)
            if len(kept) >= limit:
                break
        return kept
    return out[:limit]


def _normalise(brand: str) -> str:
    """DNS-safe brand token: lowercase, hyphens, no TLD."""
    token = brand.strip().lower()
    for suffix in (".com", ".io", ".net", ".org", ".co"):
        if token.endswith(suffix):
            token = token[: -len(suffix)]
    return "".join(ch if ch.isalnum() or ch == "-" else "-" for ch in token).strip("-")


_S3_MARKERS: tuple[tuple[str, BucketState], ...] = (
    ("<ListBucketResult", BucketState.PUBLIC_LIST),
    ("NoSuchBucket", BucketState.NOT_FOUND),
    ("AccessDenied", BucketState.ACCESS_DENIED),
    ("PermanentRedirect", BucketState.REDIRECT),
    ("AllAccessDisabled", BucketState.ACCESS_DENIED),
)

_GCS_MARKERS: tuple[tuple[str, BucketState], ...] = (
    ('"kind": "storage#objects"', BucketState.PUBLIC_LIST),
    ("No such object", BucketState.NOT_FOUND),
    ("Anonymous caller does not have storage.objects.list", BucketState.ACCESS_DENIED),
    ("The specified bucket does not exist", BucketState.NOT_FOUND),
)


def classify(provider: Provider, status: int, body: str) -> BucketState:
    """Turn a response into a bucket state.

    The subtle case is ``AccessDenied`` on listing *plus* a served object: the
    bucket is closed to enumeration but leaks individual files, which is a real
    finding and the one most easily missed because the first probe looks clean.
    """
    markers = _GCS_MARKERS if provider is Provider.GCS else _S3_MARKERS
    for marker, state in markers:
        if marker in body:
            return state
    if status == 404:
        return BucketState.NOT_FOUND
    if status == 403:
        return BucketState.ACCESS_DENIED
    if status in {301, 307}:
        return BucketState.REDIRECT
    if status == 200 and body.lstrip().startswith(("{", "<")):
        return (
            BucketState.PUBLIC_LIST if "<Key>" in body or '"name"' in body else BucketState.UNKNOWN
        )
    return BucketState.UNKNOWN


def is_finding(state: BucketState) -> bool:
    return state in (BucketState.PUBLIC_LIST, BucketState.PUBLIC_READ)


def next_action(state: BucketState) -> str:
    """The next move for each state — the difference between a queue and a list."""
    return {
        BucketState.PUBLIC_LIST: "enumerate keys, sample records for the impact artifact",
        BucketState.PUBLIC_READ: "ultra-low risk: object listing is denied but files are served",
        BucketState.EXISTS_PRIVATE: "closed; note the naming pattern for other brands/providers",
        BucketState.REDIRECT: "bucket exists in another region; retry the regional endpoint",
        BucketState.ACCESS_DENIED: "try a known object path before concluding it is closed",
        BucketState.NOT_FOUND: "name is free — check whether the target's DNS still points here",
        BucketState.UNKNOWN: "inspect the response body manually",
    }[state]
