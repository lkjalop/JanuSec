"""Entity-constrained generation (Phase 3.11).

Makes entity hallucination structurally impossible in the SHIPPED narrative, rather
than merely detected after the fact (that is the evidence-integrity gate's job — this
is the cure it is the safety net for).

Two mechanisms:

  1. build_entity_allowlist / format_allowlist_block — an explicit, enumerated
     allow-list of the entities present in the evidence, injected into the prompt as a
     hard constraint so the model is told exactly which names it may use.

  2. scrub_ungrounded_entities — a deterministic OUTPUT pass. No matter what the model
     emits, every entity-shaped token in the narrative that is not grounded in the
     evidence is replaced with either the closest allowed entity (a typo-level
     near-miss, e.g. `svr-db-01` -> `srv-db-01`) or a neutral type phrase. The
     published prose therefore cannot contain a fabricated host / IP / domain / user.
     Runs on whatever ships — LLM output, a regenerated narrative, or a fallback.
"""
from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field

from src.core.ingest.evidence_integrity import (
    _DASH_HOST_RE,
    _FQDN_RE,
    _IP_RE,
    _MITRE_ID_RE,
    _evidence_token_set,
    _is_grounded,
)

# One scanner for all three entity shapes (IP, dashed host, dotted user/FQDN).
_ENTITY_SCAN_RE = re.compile(
    r"\b(?:"
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"           # IPv4
    # Any letter-led token with >=1 dot/dash segment: covers svr-db-01, martin.chen,
    # vesper.local, beacon-c2.xyz, ghost-server-42.internal. Letter-led excludes dates
    # (2026-04-13); MITRE codes are skipped downstream by _MITRE_ID_RE.
    r"|[A-Za-z][A-Za-z0-9]*(?:[.-][A-Za-z0-9]+)+"
    r")\b"
)

_DOMAIN_TLDS = {"com", "net", "org", "io", "local", "gov", "edu", "co", "ai", "cloud", "internal"}

_REDACT = {
    "ip": "an internal address",
    "host": "an internal host",
    "domain": "an external domain",
    "user": "a user account",
}

# Attribution fields we prefer as the source of allow-list values (canonical schema).
_USER_FIELDS = ("user", "user_canonical", "actor", "username")
_IP_FIELDS = ("src_ip", "dst_ip", "ip", "client_ip", "callerIp")
_HOST_FIELDS = ("hostname", "host", "device_id", "dst_host", "src_host")
_DOMAIN_FIELDS = ("domain", "dns_query", "url", "fqdn")


@dataclass
class EntityAllowlist:
    users: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    hosts: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)

    def all_values(self) -> set[str]:
        return self.users | self.ips | self.hosts | self.domains

    def is_empty(self) -> bool:
        return not self.all_values()


def _classify_shape(tok: str) -> str:
    if _IP_RE.fullmatch(tok):
        return "ip"
    if _DASH_HOST_RE.fullmatch(tok):
        return "host"
    if "." in tok:
        tld = tok.rsplit(".", 1)[-1].lower()
        return "domain" if tld in _DOMAIN_TLDS else "user"
    return "host"


def build_entity_allowlist(evidence_rows: list[dict]) -> EntityAllowlist:
    """Enumerate the entities present in the evidence, preferring canonical
    attribution fields and falling back to regex over all string values."""
    al = EntityAllowlist()
    for row in evidence_rows or []:
        if not isinstance(row, dict):
            continue
        for f in _USER_FIELDS:
            v = row.get(f)
            if isinstance(v, str) and v.strip():
                al.users.add(v.strip().lower())
        for f in _IP_FIELDS:
            v = row.get(f)
            if isinstance(v, str) and _IP_RE.fullmatch(v.strip()):
                al.ips.add(v.strip())
        for f in _HOST_FIELDS:
            v = row.get(f)
            if isinstance(v, str) and v.strip():
                al.hosts.add(v.strip().lower())
        for f in _DOMAIN_FIELDS:
            v = row.get(f)
            if isinstance(v, str) and v.strip():
                al.domains.add(v.strip().lower())
    return al


def format_allowlist_block(allowlist: EntityAllowlist, *, max_per_type: int = 20) -> str:
    """Prompt block enumerating the allowed entities as a hard constraint."""
    if allowlist.is_empty():
        return ""
    lines = ["ENTITY ALLOW-LIST — you may name ONLY the entities below. Writing ANY other",
             "host, IP, domain, or username is a critical error and will be rejected:"]
    if allowlist.users:
        lines.append("  Users: " + ", ".join(sorted(allowlist.users)[:max_per_type]))
    if allowlist.ips:
        lines.append("  IPs: " + ", ".join(sorted(allowlist.ips)[:max_per_type]))
    if allowlist.hosts:
        lines.append("  Hosts: " + ", ".join(sorted(allowlist.hosts)[:max_per_type]))
    if allowlist.domains:
        lines.append("  Domains: " + ", ".join(sorted(allowlist.domains)[:max_per_type]))
    return "\n".join(lines)


_TCODE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _tcode_base(code: str) -> str:
    return code.split(".", 1)[0].upper()


def correct_mitre_ids(text: str, allowed_tcodes: set[str]) -> tuple[str, list[dict]]:
    """Remove MITRE technique IDs from prose that are NOT in the deterministic
    allowed set. 14B models routinely invent wrong/deprecated T-codes (e.g. T1547
    for OAuth device-code, T1075 for WMI) even though the platform knows the correct
    ones (T1528, T1047). The grounding gate deliberately ignores T-codes, so this is
    the separate correction pass. A prose code is kept if it — or its base technique —
    is in the allowed set (so T1558 is kept when T1558.003 is allowed). Returns the
    corrected text and a list of removed codes. No-op when `allowed_tcodes` is empty
    (nothing to validate against)."""
    if not text or not allowed_tcodes:
        return text, []
    allowed = {c.upper() for c in allowed_tcodes}
    allowed_bases = {_tcode_base(c) for c in allowed}
    removed: list[dict] = []

    def _ok(code: str) -> bool:
        c = code.upper()
        return c in allowed or _tcode_base(c) in allowed_bases

    def _replace(m: re.Match) -> str:
        code = m.group(0)
        if _ok(code):
            return code
        removed.append({"code": code, "action": "removed_ungrounded_mitre"})
        return "\x00"  # sentinel, cleaned up below

    out = _TCODE_RE.sub(_replace, text)
    if removed:
        # Tidy the holes: drop an empty parenthetical the code left behind, collapse
        # stray separators/whitespace.
        out = re.sub(r"\(\s*\x00\s*\)", "", out)          # "(T1547)" -> ""
        out = re.sub(r"\s*\x00", "", out)                  # " T1547"  -> ""
        out = re.sub(r"\(\s*\)", "", out)                  # leftover "()"
        out = re.sub(r"\s+,", ",", out)
        out = re.sub(r",\s*,", ",", out)
        out = re.sub(r"\s{2,}", " ", out).strip()
    return out, removed


def scrub_ungrounded_entities(
    text: str,
    evidence_rows: list[dict],
    *,
    similarity_threshold: float = 0.82,
) -> tuple[str, list[dict]]:
    """Deterministically remove ungrounded entities from `text`.

    Every entity-shaped token not grounded in the evidence is replaced with the closest
    allowed entity (if similar enough) or a neutral type phrase. Returns the scrubbed
    text and a list of {original, replacement, action, ratio} records."""
    if not text or not text.strip():
        return text, []
    tokens = _evidence_token_set(evidence_rows)
    # Substitution candidates: compound evidence tokens (dotted/dashed) of reasonable length.
    candidates = [t for t in tokens if ("." in t or "-" in t) and len(t) >= 5]
    redactions: list[dict] = []

    def _replace(m: re.Match) -> str:
        tok = m.group(0)
        low = tok.lower()
        if _MITRE_ID_RE.match(low):
            return tok
        if _is_grounded(low, tokens):
            return tok
        # Try a typo-level fuzzy substitution against real evidence entities.
        best, best_r = None, 0.0
        for cand in candidates:
            r = difflib.SequenceMatcher(None, low, cand).ratio()
            if r > best_r:
                best_r, best = r, cand
        if best and best_r >= similarity_threshold:
            redactions.append({"original": tok, "replacement": best, "action": "substituted", "ratio": round(best_r, 2)})
            return best
        phrase = _REDACT[_classify_shape(low)]
        redactions.append({"original": tok, "replacement": phrase, "action": "redacted", "ratio": 0.0})
        return phrase

    scrubbed = _ENTITY_SCAN_RE.sub(_replace, text)
    return scrubbed, redactions
