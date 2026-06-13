"""Verdict engine — cluster ranking, quality gates, and config constants for Tier-1 prefill."""
from __future__ import annotations

import re
import os
import time
from typing import Any

# ── Config constants ───────────────────────────────────────────────────────────

# Config flag — set to False in tests to skip actual LLM calls
PREFILL_ENABLED = True
PREFILL_DEFAULT_MODEL = 'qwen3:14b'
PREFILL_TOP_N = 3
PREFILL_MAX_TOKENS = 3000
PREFILL_TIMEOUT_S = int(os.getenv('PREFILL_TIMEOUT_S') or os.getenv('OLLAMA_TIMEOUT_SECONDS') or os.getenv('LLM_TIMEOUT_SECONDS') or '45')

_CONFIDENCE_FLOOR_CONFIRMED = 0.75
_CONFIDENCE_FLOOR_LIKELY    = 0.55
_EVIDENCE_FILL_FLOOR        = 0.60

# ── Shared constants ───────────────────────────────────────────────────────────

# Import _SEV_RANK from evidence_binder so callers only need one import
from .evidence_binder import _SEV_RANK  # noqa: F401

_JARGON_PATTERNS = [
    re.compile(r'\bT\d{4}(\.\d{3})?\b'),           # MITRE T-codes e.g. T1110.003
    re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),  # raw IPv4
    re.compile(r'\b(sourcetype|index|host)\s*='),   # Splunk SPL
    re.compile(r'\b(SecurityEvent|SigninLogs|AuditLogs)\s*\|'),  # KQL table pipes
]

_NEW_SCHEMA_PASS_THROUGH = {
    'what_happened', 'root_cause', 'evidence_chain', 'observed_impact',
    'evidence_gaps', 'immediate_actions',
}


# ── Cluster ranking ───────────────────────────────────────────────────────────

def _rank_clusters(clusters: list[dict]) -> list[dict]:
    """Sort clusters: confirmed > likely > uncertain > benign, then by row count."""
    verdict_rank = {
        'CONFIRMED': 5,
        'LIKELY REAL': 4,
        'LIKELY': 4,
        'UNCERTAIN': 3,
        'BENIGN': 1,
    }

    def _score(c: dict) -> tuple[int, int, int]:
        verdict = str(c.get('verdict') or c.get('final_verdict') or '').upper()
        vr = max((verdict_rank[k] for k in verdict_rank if k in verdict), default=2)
        sr = _SEV_RANK.get(str(c.get('severity') or '').lower(), 0)
        rc = len(c.get('row_refs') or [])
        return (vr, sr, rc)

    return sorted(clusters, key=_score, reverse=True)


# ── Entity pin quality gate ───────────────────────────────────────────────────

def _validate_entity_pins(prefill: dict, allowed: set[str]) -> dict:
    """Check that T1 output doesn't reference entities outside the allowed set.

    Scans incident_name, headline_subtitle, short_narrative, top_actions for
    capitalised multi-word tokens that look like proper nouns but don't appear
    in the allowed set. Returns a quality report.
    """
    # Tokens that are known safe generic security words — never flag these
    _GENERIC_OK = {
        'credential', 'spray', 'mfa', 'fatigue', 'pivot', 'lateral', 'movement',
        'persistence', 'exfiltration', 'bec', 'worm', 'supply', 'chain',
        'compromise', 'phishing', 'ransomware', 'c2', 'beacon', 'attacker',
        'adversary', 'threat', 'actor', 'malicious', 'suspicious', 'anomalous',
        'identity', 'network', 'endpoint', 'cloud', 'azure', 'okta', 'aws',
        'mitre', 'att&ck', 'high', 'medium', 'low', 'critical', 'confirmed',
        'likely', 'uncertain', 'benign', 'soc', 'analyst', 'hunter', 'forensics',
        'imap4', 'smtp', 'bcc', 'dns', 'kql', 'spl', 'edr', 'siem', 'ngfw',
        # Generic verdict / security classification terms
        'breach', 'intrusion', 'incident', 'attack', 'exploit', 'payload',
        'escalation', 'exfil', 'recon', 'execution', 'discovery', 'collection',
        'validated', 'breach', 'rbac', 'iam', 'mfa', 'sspr', 'sso', 'saml',
        'kubernetes', 'k8s', 'container', 'docker', 'pod', 'cluster', 'node',
        'vpc', 'sg', 'acl', 'nsg', 'waf', 'cdn', 'lb', 'nat', 'vpn',
        'api', 'sdk', 'cli', 'gui', 'ui', 'rest', 'graphql', 'grpc',
        'ad', 'ldap', 'kerberos', 'ntlm', 'spn', 'dce', 'rpc', 'smb',
        'lsa', 'sam', 'gpo', 'ou', 'dc', 'ca', 'pki', 'cert', 'acme',
        'cve', 'nvd', 'cvss', 'cwe', 'osint', 'ioc', 'ttp', 'apt',
    }

    # Scan text fields for suspicious capitalised tokens
    text_to_scan = ' '.join([
        prefill.get('incident_name', ''),
        prefill.get('headline_subtitle', ''),
        prefill.get('short_narrative', ''),
        ' '.join(prefill.get('top_actions', [])),
    ])

    # Identifier-shaped tokens only. The final all-caps branch REQUIRES a digit
    # (AKIA1234EXAMPLE, host SVR01) — plain all-caps English words (RULES, MODE, STYLIST,
    # MITRE section headers) are NOT entities and must not force a narration fallback.
    candidate_tokens = re.findall(
        r'\b([A-Z][a-z]{2,}\.[A-Za-z]{2,}|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}'
        r'|[A-Z]{2,}[-_][A-Z0-9]{2,}|[A-Z]{2,}[0-9][A-Z0-9]{2,})\b',
        text_to_scan,
    )

    flagged: list[str] = []
    for token in candidate_tokens:
        tl = token.lower()
        if tl in _GENERIC_OK:
            continue
        # Pure-hex tokens (hash fragments, cluster-id suffixes like BADD91DA) are not
        # proper-noun entities — a real IOC hash is validated as evidence elsewhere, not
        # pinned here. Skip them so they don't force a narration fallback.
        if len(tl) >= 8 and all(c in "0123456789abcdef" for c in tl):
            continue
        # Check if this token (or a substring) is in the allowed entity set
        matched = any(
            tl in entity or entity in tl
            for entity in allowed
            if len(entity) > 3
        )
        if not matched:
            flagged.append(token)

    passed = len(flagged) == 0
    return {
        'passed': passed,
        'flagged_tokens': list(set(flagged)),
        'checked_at': int(time.time()),
    }


# ── Narrative quality check ───────────────────────────────────────────────────

def _narrative_is_technical(text: str) -> bool:
    """Return True if text contains jargon that belongs in evidence fields, not narratives."""
    if not isinstance(text, str):
        return False
    return any(p.search(text) for p in _JARGON_PATTERNS)


# ── Verdict gating ────────────────────────────────────────────────────────────

def _gated_verdict(raw_verdict: str, confidence: float, fill_rate: float) -> str:
    """
    Three-valued gating for VALIDATED_BREACH verdicts.
    CONFIRMED_BREACH   — confidence >= 0.75 AND evidence fill-rate >= 0.60
    LIKELY_BREACH      — confidence >= 0.55 (human review required)
    INVESTIGATION_REQUIRED — below both floors

    Non-breach verdicts pass through unchanged.
    """
    if raw_verdict not in ('VALIDATED_BREACH', 'CONFIRMED_INTRUSION'):
        return raw_verdict
    if confidence >= _CONFIDENCE_FLOOR_CONFIRMED and fill_rate >= _EVIDENCE_FILL_FLOOR:
        return 'CONFIRMED_BREACH'
    if confidence >= _CONFIDENCE_FLOOR_LIKELY:
        return 'LIKELY_BREACH'
    return 'INVESTIGATION_REQUIRED'
