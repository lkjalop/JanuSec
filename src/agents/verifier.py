"""
Verifier agent — cross-checks Investigator findings independently.

Runs in a SEPARATE LLM context from the Planner to defend against
prompt injection propagation. For each RawFinding:

  0. Independent re-derivation from raw DuckDB rows (Fix 3)
  1. Engagement scope check — is this a pentest/engagement actor?
  2. CorrectiveRAG check — structured (type, actor, phase) matching (Fix 6)
  3. Multi-source check — does evidence come from ≥2 independent sources?
  4. Canary check — are test/canary events still correctly classified?
  5. DREAD scoring — algorithmic, not LLM-based
  6. Compliance tagging — rule-based (compliance_tags.py)
  7. Confidence computation — reverification-weighted, not saturating (Fix 5)

Outputs: verified[], rejected[], weak[]
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Set

from src.agents.types import (
    Gap,
    InvestigationContext,
    RawFinding,
    RejectionReason,
    VerifiedFinding,
)

LOGGER = logging.getLogger(__name__)


# ── Fix 3: Independent re-derivation ─────────────────────────────────────────

def _extract_claim_keywords(summary: str) -> List[str]:
    """Extract investigation-relevant keywords from a finding summary."""
    # Common security keywords to look for in DuckDB
    _SECURITY_TERMS = [
        "lsass", "comsvcs", "mimikatz", "credential", "rdp", "psexec",
        "wmiexec", "lateral", "assumerole", "exfil", "rclone", "mega",
        "beacon", "c2", "dns tunnel", "cobalt", "persistence",
        "scheduled task", "phishing", "container escape", "daemonset",
        "snowflake", "copy_into", "backblaze", "hetzner",
    ]
    summary_lower = summary.lower()
    return [kw for kw in _SECURITY_TERMS if kw in summary_lower]


def _keywords_to_sql(keywords: List[str]) -> str:
    """Convert keywords to a safe SQL WHERE fragment for DuckDB."""
    if not keywords:
        return "1=1"
    conditions = []
    for kw in keywords[:5]:
        # Sanitise: only allow alphanumeric + underscore + space
        safe_kw = re.sub(r"[^a-zA-Z0-9_ ]", "", kw)
        if safe_kw:
            conditions.append(f"LOWER(raw_text) LIKE '%{safe_kw}%'")
    return " OR ".join(conditions) if conditions else "1=1"


def _detect_contradictions(rows: List[Dict], finding: RawFinding) -> List[str]:
    """Detect contradictions between DuckDB rows and finding claims."""
    contradictions = []
    # If finding claims a specific actor but rows show a different one
    claimed_actor = finding.evidence.get("actor") or finding.evidence.get("user")
    if claimed_actor and rows:
        row_actors = {r.get("user") or r.get("actor") for r in rows if isinstance(r, dict)}
        row_actors.discard(None)
        if row_actors and claimed_actor not in row_actors:
            contradictions.append(f"claimed actor '{claimed_actor}' not in row actors: {row_actors}")
    return contradictions


def _reverify_from_evidence(
    finding: RawFinding,
    context: InvestigationContext,
) -> Dict[str, Any]:
    """Independent re-derivation of the finding from raw rows.

    Returns reverification metadata; if rows_corroborated == 0
    or contradictions is non-empty, the caller should reject/weaken.
    """
    try:
        from src.core.ingest.store import get_assessment_events  # type: ignore[attr-defined]
    except (ImportError, AttributeError):
        # Store not available (tests, offline mode) — return partial verification
        return {
            "query_executed": "N/A (store unavailable)",
            "rows_checked": 0,
            "rows_corroborated": 0,
            "contradictions": [],
            "store_available": False,
        }

    claim_keywords = _extract_claim_keywords(finding.summary)
    row_refs = (finding.evidence.get("row_refs")
                or finding.evidence.get("sample_row_ids")
                or [])

    try:
        sql_where = _keywords_to_sql(claim_keywords)
        rows = get_assessment_events(
            context.assessment_id,
            extra_where=sql_where,
            limit=50,
        )
    except Exception as exc:
        LOGGER.warning("reverification query failed: %s", exc)
        return {
            "query_executed": _keywords_to_sql(claim_keywords),
            "rows_checked": 0,
            "rows_corroborated": 0,
            "contradictions": [],
            "store_available": True,
            "error": str(exc),
        }

    corroborated = sum(1 for r in rows if isinstance(r, dict) and r.get("row_id") in row_refs)
    # If no row_refs provided, corroborate by finding matching rows
    if not row_refs and rows:
        corroborated = len(rows)

    contradictions = _detect_contradictions(rows, finding)

    return {
        "query_executed": sql_where,
        "rows_checked": len(rows),
        "rows_corroborated": corroborated,
        "contradictions": contradictions,
        "store_available": True,
    }


# ── Fix 6: Structured engagement scope check ─────────────────────────────────

def _extract_finding_signature(finding: RawFinding) -> Dict[str, str]:
    """Extract structured signature from a finding for corrective RAG matching."""
    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
    summary_lower = finding.summary.lower()

    # Derive phase from summary keywords
    phase = "unknown"
    _PHASE_KEYWORDS = {
        "scanning": ["scan", "recon", "enumerat", "discovery"],
        "initial_access": ["phish", "spear", "initial access", "bec"],
        "credential_access": ["credential", "lsass", "mimikatz", "comsvcs.dll", "token", "dump", "kerberoast"],
        "execution": ["exec", "powershell", "cmd.exe", "wscript", "mshta"],
        "persistence": ["persist", "scheduled task", "registry", "backdoor"],
        "privilege_escalation": ["priv", "escalat", "admin", "sudo"],
        "lateral_movement": ["lateral", "rdp", "psexec", "wmi", "smb"],
        "collection": ["collect", "staging", "archive"],
        "exfiltration": ["exfil", "rclone", "mega", "backblaze", "copy_into"],
    }
    for p, keywords in _PHASE_KEYWORDS.items():
        if any(kw in summary_lower for kw in keywords):
            phase = p
            break

    return {
        "actor": evidence.get("user") or evidence.get("actor") or "",
        "ip": evidence.get("src_ip") or evidence.get("ip") or "",
        "phase": phase,
    }


def _check_engagement_scope(
    finding: RawFinding,
    engagement_actors: Set[str],
    engagement_ips: Set[str],
) -> Optional[RejectionReason]:
    """Return structured rejection if finding is within pentest/engagement scope."""
    evidence = finding.evidence
    if not isinstance(evidence, dict):
        return None

    sig = _extract_finding_signature(finding)

    # Check actors
    for actor in engagement_actors:
        if actor.lower() in str(evidence).lower():
            return RejectionReason(
                type="engagement_scope",
                actor=actor,
                ip=sig["ip"],
                phase=sig["phase"],
                detail=f"engagement actor {actor} in phase {sig['phase']}",
            )

    # Check IPs
    for ip in engagement_ips:
        if ip in str(evidence):
            return RejectionReason(
                type="engagement_scope",
                actor=sig["actor"],
                ip=ip,
                phase=sig["phase"],
                detail=f"engagement IP {ip} in phase {sig['phase']}",
            )
    return None


def _check_corrective_rag(
    finding: RawFinding,
    fp_patterns: List[RejectionReason],
) -> Optional[RejectionReason]:
    """Return rejection if finding matches a known FP — structured matching.

    Matches on (type, actor, phase) tuples. A pentester in phase=scanning
    is NOT the same as that pentester in phase=escalation.
    """
    sig = _extract_finding_signature(finding)

    for fp in fp_patterns:
        if fp.type == "engagement_scope":
            # Only match if actor AND phase both match
            if (fp.actor and fp.actor.lower() == sig["actor"].lower()
                    and fp.phase == sig["phase"]):
                return RejectionReason(
                    type="known_fp",
                    actor=sig["actor"],
                    phase=sig["phase"],
                    detail=f"corrective RAG: actor={fp.actor} phase={fp.phase} (same as prior rejection)",
                )
        elif fp.type == "known_fp":
            if (fp.actor and fp.actor.lower() == sig["actor"].lower()
                    and fp.phase == sig["phase"]):
                return fp
    return None


def _compute_dread_score(finding: RawFinding) -> float:
    """Lightweight algorithmic DREAD score (not LLM-based)."""
    score = 5.0

    if finding.source_count >= 3:
        score += 2.0
    elif finding.source_count >= 2:
        score += 1.0

    if finding.data_volume_bytes > 10000:
        score += 0.5

    return min(score, 10.0)


def _derive_compliance_tags(finding: RawFinding) -> List[Dict[str, str]]:
    """Derive compliance controls from finding evidence."""
    try:
        from src.prefill.compliance_tags import derive_controls_breached
        fragments = {
            "summary": finding.summary,
            "evidence": str(finding.evidence) if isinstance(finding.evidence, dict) else "",
        }
        return derive_controls_breached(fragments)
    except Exception:
        return []


# ── Fix 5: Non-saturating confidence ─────────────────────────────────────────

def _compute_confidence(
    vf: VerifiedFinding,
    gaps: List[Gap] | None = None,
) -> float:
    """Confidence that doesn't saturate near 0.95.

    Primary signal: reverification corroboration ratio.
    Secondary: source diversity and DREAD score.
    Penalties: gaps and contradictions.
    """
    rev = vf.reverification or {}
    rows_checked = rev.get("rows_checked", 0)
    rows_corroborated = rev.get("rows_corroborated", 0)
    store_available = rev.get("store_available", False)

    # Corroboration ratio is the floor signal
    if not store_available:
        corroboration = 0.5   # store unavailable — neutral
    elif rows_checked == 0:
        corroboration = 0.3   # no independent check possible
    else:
        corroboration = rows_corroborated / rows_checked

    # Source diversity (telemetry types, not raw row count)
    source_diversity = min(vf.raw.source_count / 4.0, 1.0)

    # DREAD contributes only modestly
    dread_factor = vf.dread_score / 10.0

    base = 0.4 * corroboration + 0.4 * source_diversity + 0.2 * dread_factor

    # Penalties
    gap_penalty = 0.0
    if gaps:
        gap_penalty = sum(0.05 for g in gaps if g.confidence_cap < 1.0)

    contradiction_penalty = 0.15 if rev.get("contradictions") else 0.0

    confidence = max(base - gap_penalty - contradiction_penalty, 0.0)

    # Hard cap from worst gap
    if gaps:
        worst_cap = min((g.confidence_cap for g in gaps), default=1.0)
        confidence = min(confidence, worst_cap)

    return round(confidence, 2)


# ── Main verify function ─────────────────────────────────────────────────────

def verify(
    findings: List[RawFinding],
    context: InvestigationContext,
    *,
    engagement_actors: Optional[Set[str]] = None,
    engagement_ips: Optional[Set[str]] = None,
    fp_patterns: Optional[List[RejectionReason]] = None,
    canary_events: Optional[Set[str]] = None,
    gaps: Optional[List[Gap]] = None,
) -> tuple[List[VerifiedFinding], List[VerifiedFinding], List[VerifiedFinding]]:
    """Verify a batch of raw findings.

    Returns:
        (verified, rejected, weak)
    """
    engagement_actors = engagement_actors or set()
    engagement_ips = engagement_ips or set()
    fp_patterns = fp_patterns or []
    gaps = gaps or []

    verified: List[VerifiedFinding] = []
    rejected: List[VerifiedFinding] = []
    weak: List[VerifiedFinding] = []

    for finding in findings:
        vf = VerifiedFinding(
            raw=finding,
            dread_score=_compute_dread_score(finding),
            compliance_controls=_derive_compliance_tags(finding),
        )

        # 0. Independent re-derivation (Fix 3)
        reverification = _reverify_from_evidence(finding, context)
        vf.reverification = reverification

        if reverification.get("store_available", False):
            if reverification["rows_corroborated"] == 0 and reverification["rows_checked"] > 0:
                vf.rejection_reason = RejectionReason(
                    type="no_corroboration",
                    detail=f"no corroborating rows in independent query ({reverification['query_executed']})",
                )
                vf.confidence = 0.0
                rejected.append(vf)
                LOGGER.info("rejected (no corroboration): %s", finding.summary[:80])
                continue

            if reverification.get("contradictions"):
                vf.rejection_reason = RejectionReason(
                    type="contradiction",
                    detail=f"contradictions: {reverification['contradictions']}",
                )
                vf.confidence = 0.0
                rejected.append(vf)
                LOGGER.info("rejected (contradiction): %s", finding.summary[:80])
                continue

        # 1. Engagement scope check (structured)
        scope_reason = _check_engagement_scope(finding, engagement_actors, engagement_ips)
        if scope_reason:
            vf.rejection_reason = scope_reason
            vf.confidence = 0.0
            rejected.append(vf)
            LOGGER.info("rejected (engagement scope): %s", scope_reason.detail)
            continue

        # 2. CorrectiveRAG check (structured, Fix 6)
        fp_reason = _check_corrective_rag(finding, fp_patterns)
        if fp_reason:
            vf.rejection_reason = fp_reason
            vf.confidence = 0.1
            rejected.append(vf)
            LOGGER.info("rejected (corrective RAG): %s", fp_reason.detail)
            continue

        # 3. Multi-source check
        if finding.source_count < 2:
            vf.weak = True
            vf.confidence = _compute_confidence(vf, gaps)
            weak.append(vf)
            LOGGER.info("weak finding (single source): %s", finding.summary[:80])
            continue

        # 4. Canary check
        if canary_events and finding.summary in canary_events:
            vf.rejection_reason = RejectionReason(
                type="canary_failure",
                detail="canary event appeared in findings — possible injection",
            )
            vf.confidence = 0.0
            rejected.append(vf)
            LOGGER.error("CANARY triggered: %s", finding.summary[:80])
            continue

        # 5. Compute non-saturating confidence (Fix 5)
        vf.confidence = _compute_confidence(vf, gaps)

        verified.append(vf)
        LOGGER.info("verified [%.2f]: %s", vf.confidence, finding.summary[:80])

    return verified, rejected, weak
