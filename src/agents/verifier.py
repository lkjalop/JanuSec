"""
Verifier agent — cross-checks Investigator findings independently.

Runs in a SEPARATE LLM context from the Planner to defend against
prompt injection propagation. For each RawFinding:

  1. Engagement scope check — is this a pentest/engagement actor?
  2. CorrectiveRAG check — is this a known false positive pattern?
  3. Multi-source check — does evidence come from ≥2 independent sources?
  4. Canary check — are test/canary events still correctly classified?
  5. DREAD scoring — algorithmic, not LLM-based
  6. Compliance tagging — rule-based (compliance_tags.py)

Outputs: verified[], rejected[], weak[]
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set

from src.agents.types import (
    InvestigationContext,
    RawFinding,
    VerifiedFinding,
)

LOGGER = logging.getLogger(__name__)


def _check_engagement_scope(
    finding: RawFinding,
    engagement_actors: Set[str],
    engagement_ips: Set[str],
) -> Optional[str]:
    """Return rejection reason if finding is within pentest/engagement scope."""
    evidence = finding.evidence
    if not isinstance(evidence, dict):
        return None

    # Check if any evidence field matches known engagement actors/IPs
    evidence_text = str(evidence).lower()
    for actor in engagement_actors:
        if actor.lower() in evidence_text:
            return f"engagement actor: {actor}"
    for ip in engagement_ips:
        if ip in evidence_text:
            return f"engagement IP: {ip}"
    return None


def _check_corrective_rag(
    finding: RawFinding,
    fp_patterns: List[str],
) -> Optional[str]:
    """Return rejection reason if finding matches a known FP pattern."""
    summary_lower = finding.summary.lower()
    for pattern in fp_patterns:
        if pattern.lower() in summary_lower:
            return f"known FP pattern: {pattern}"
    return None


def _compute_dread_score(finding: RawFinding) -> float:
    """Lightweight algorithmic DREAD score (not LLM-based).

    Uses heuristics from the finding metadata. Full LLM-based DREAD
    scoring happens later in prefill; this is a quick gate score.
    """
    score = 5.0  # baseline

    # Multi-source evidence boosts confidence
    if finding.source_count >= 3:
        score += 2.0
    elif finding.source_count >= 2:
        score += 1.0

    # Data volume heuristic (more data = more evidence)
    if finding.data_volume_bytes > 10000:
        score += 0.5

    # Cap at 10
    return min(score, 10.0)


def _derive_compliance_tags(finding: RawFinding) -> List[Dict[str, str]]:
    """Derive compliance controls from finding evidence."""
    try:
        from src.prefill.compliance_tags import derive_controls_breached
        # Build pseudo-fragments from finding for tag derivation
        fragments = {
            "summary": finding.summary,
            "evidence": str(finding.evidence) if isinstance(finding.evidence, dict) else "",
        }
        return derive_controls_breached(fragments)
    except Exception:
        return []


def verify(
    findings: List[RawFinding],
    context: InvestigationContext,
    *,
    engagement_actors: Optional[Set[str]] = None,
    engagement_ips: Optional[Set[str]] = None,
    fp_patterns: Optional[List[str]] = None,
    canary_events: Optional[Set[str]] = None,
) -> tuple[List[VerifiedFinding], List[VerifiedFinding], List[VerifiedFinding]]:
    """Verify a batch of raw findings.

    Returns:
        (verified, rejected, weak)
        - verified: high-confidence findings that passed all checks
        - rejected: findings that failed a check (reason recorded)
        - weak: single-source findings flagged for human review
    """
    engagement_actors = engagement_actors or set()
    engagement_ips = engagement_ips or set()
    fp_patterns = fp_patterns or []

    verified: List[VerifiedFinding] = []
    rejected: List[VerifiedFinding] = []
    weak: List[VerifiedFinding] = []

    for finding in findings:
        vf = VerifiedFinding(
            raw=finding,
            dread_score=_compute_dread_score(finding),
            compliance_controls=_derive_compliance_tags(finding),
        )

        # 1. Engagement scope check
        scope_reason = _check_engagement_scope(finding, engagement_actors, engagement_ips)
        if scope_reason:
            vf.rejection_reason = scope_reason
            vf.confidence = 0.0
            rejected.append(vf)
            LOGGER.info("rejected (engagement scope): %s", scope_reason)
            continue

        # 2. CorrectiveRAG check
        fp_reason = _check_corrective_rag(finding, fp_patterns)
        if fp_reason:
            vf.rejection_reason = fp_reason
            vf.confidence = 0.1
            rejected.append(vf)
            LOGGER.info("rejected (corrective RAG): %s", fp_reason)
            continue

        # 3. Multi-source check
        if finding.source_count < 2:
            vf.weak = True
            vf.confidence = 0.4 + (vf.dread_score / 20.0)  # lower confidence
            weak.append(vf)
            LOGGER.info("weak finding (single source): %s", finding.summary[:80])
            continue

        # 4. Canary check (if canary events provided)
        if canary_events and finding.summary in canary_events:
            # Canary should NOT appear in findings — if it does, something is wrong
            vf.rejection_reason = "canary event appeared in findings — possible injection"
            vf.confidence = 0.0
            rejected.append(vf)
            LOGGER.error("CANARY triggered: %s", finding.summary[:80])
            continue

        # 5. Confidence from DREAD + multi-source
        base_confidence = 0.5 + (finding.source_count * 0.1)
        dread_bonus = vf.dread_score / 20.0
        vf.confidence = min(base_confidence + dread_bonus, 1.0)

        verified.append(vf)
        LOGGER.info("verified [%.2f]: %s", vf.confidence, finding.summary[:80])

    return verified, rejected, weak
