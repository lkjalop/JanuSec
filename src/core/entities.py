"""Canonical entity extraction — the single source of truth for user / IP / host
identifiers pulled out of a normalized event row.

Before this module, ~12 call sites (critic, cluster_merge, cluster_narrator,
baseline_context, evidence_binder, enrichment, story_coherence, decision_support,
llm_compare, …) each rolled their own field list and normalization. The divergence
was not cosmetic: the critic's hallucination check used a *narrower* field set than
the narrator's, so the two disagreed on what counted as a grounded entity. Consolidating
here removes that whole class of drift.

Two shapes are exposed:
  * ``extract_entities(row)`` — a flat, normalized set of every identifier in a row
    (users + IPs + hosts, plus the short hostname of any FQDN). This is what the
    hallucination/grounding checks need.
  * ``extract_typed(rows)`` — sorted, de-duplicated (users, ips, hosts) lists across a
    set of rows, with users/hosts canonical-preferred. This is what cluster rollups
    (shared_users / shared_ips / shared_hosts) need.

Field lists are the *superset* of every prior call site, so no consumer loses coverage.
"""
from __future__ import annotations

from typing import Iterable

# Superset of every prior extractor's fields. Order within a tier is priority order
# (first non-empty wins for the "primary" helpers).
USER_FIELDS: tuple[str, ...] = (
    "user_canonical", "user", "username", "account_name",
    "userPrincipalName", "user_principal_name", "spn", "service_name",
)
IP_FIELDS: tuple[str, ...] = (
    "src_ip", "dst_ip", "ip", "client_address",
)
HOST_FIELDS: tuple[str, ...] = (
    "hostname", "host", "src_host", "dst_host", "computer_name", "domain_controller",
)

# Values that are never real identifiers (union of every prior stopword set).
STOPWORDS = frozenset({
    "-", "n/a", "none", "null", "0.0.0.0", "system", "root", "unknown", "localhost", "",
})

_MIN_LEN = 2  # tokens this short are noise (matches the narrator's prior behavior)

# Loose stopwords for the typed/rollup path — only unambiguous non-identifiers, so
# cluster shared_* rollups keep the exact membership they had before this module
# (which did not drop "system"/"root" or short tokens).
_LOOSE_STOPWORDS = frozenset({"-", "n/a", "none", "null", "0.0.0.0", ""})


def _norm(value: object, *, strict: bool = True) -> str:
    """Lowercase/strip a value. strict=True applies the narrator's stopword + min-length
    filtering (for hallucination checks); strict=False only drops unambiguous
    non-identifiers (for cluster rollups that must preserve prior membership)."""
    if value is None:
        return ""
    s = str(value).strip().lower()
    if not s:
        return ""
    if strict:
        if s in STOPWORDS or len(s) <= _MIN_LEN:
            return ""
    else:
        if s in _LOOSE_STOPWORDS:
            return ""
    return s


def _is_ipish(s: str) -> bool:
    # crude: an all-digits-and-dots token is an IP, not an FQDN
    return bool(s) and s.replace(".", "").isdigit()


def _add_with_short_host(out: set[str], value: str) -> None:
    """Add a value and, for an FQDN, also its short hostname (dc-01 from dc-01.corp.local)."""
    if not value:
        return
    out.add(value)
    if "." in value and not _is_ipish(value):
        short = value.split(".")[0]
        if len(short) > _MIN_LEN:
            out.add(short)


def extract_users(row: dict) -> set[str]:
    return {v for v in (_norm(row.get(f)) for f in USER_FIELDS) if v}


def extract_ips(row: dict) -> set[str]:
    return {v for v in (_norm(row.get(f)) for f in IP_FIELDS) if v}


def extract_hosts(row: dict) -> set[str]:
    return {v for v in (_norm(row.get(f)) for f in HOST_FIELDS) if v}


def extract_entities(row: dict) -> set[str]:
    """Flat normalized set of all identifiers in a row (+ short hostnames for FQDNs).

    This is the canonical input for hallucination/grounding checks — every consumer
    that asks "is this entity present in the evidence?" must use this so the answer
    is identical everywhere.
    """
    out: set[str] = set()
    for v in extract_users(row):
        _add_with_short_host(out, v)
    for v in extract_ips(row):
        out.add(v)
    for v in extract_hosts(row):
        _add_with_short_host(out, v)
    return out


def primary_user(row: dict) -> str:
    """First non-empty user field in priority order (canonical preferred). Loose
    filtering — a short but real username is kept."""
    for f in USER_FIELDS:
        v = _norm(row.get(f), strict=False)
        if v:
            return v
    return ""


def primary_host(row: dict) -> str:
    for f in HOST_FIELDS:
        v = _norm(row.get(f), strict=False)
        if v:
            return v
    return ""


def primary_ip(row: dict) -> str:
    # src_ip preferred (the actor's source), then the rest
    for f in IP_FIELDS:
        v = _norm(row.get(f), strict=False)
        if v:
            return v
    return ""


def extract_typed(rows: Iterable[dict]) -> tuple[list[str], list[str], list[str]]:
    """Sorted, de-duplicated (users, ips, hosts) across *rows*, preserving the historical
    cluster-rollup membership (loose filtering, src_ip-only IPs, canonical-preferred
    users/hosts — one per row). Intended as the drop-in for cluster_merge shared_*.
    """
    users: set[str] = set()
    ips: set[str] = set()
    hosts: set[str] = set()
    for r in rows:
        u = _norm(r.get("user_canonical") or r.get("user"), strict=False)
        if u:
            users.add(u)
        ip = _norm(r.get("src_ip"), strict=False)
        if ip:
            ips.add(ip)
        h = _norm(r.get("hostname") or r.get("host"), strict=False)
        if h:
            hosts.add(h)
    return sorted(users), sorted(ips), sorted(hosts)
