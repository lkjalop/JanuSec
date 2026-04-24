"""Deterministic verdict derivation for correlation clusters.

Reads data already on the cluster object (confidence_meter, severity, tier1_prefill._cot,
tier1_prefill.verdict_reasoning) and produces a human-readable verdict label + rationale.

Six-label ladder (highest → lowest confidence):
  VALIDATED_BREACH       — strong multi-source evidence, LLM says REAL, conf >= 80
  CONFIRMED_INTRUSION    — high-confidence threat, LLM says REAL, conf >= 60
  LIKELY_COMPROMISE      — probable threat activity, conf >= 40 or LLM leans real
  SUSPICIOUS_ACTIVITY    — anomalous but insufficient evidence to confirm
  INSUFFICIENT_TELEMETRY — too few data points to assess reliably
  BENIGN_EXPECTED        — explainable by legitimate activity
"""
from __future__ import annotations

import re
from typing import Optional


# ── CoT / reasoning parsing ───────────────────────────────────────────────────

_RE_FINAL_VERDICT = re.compile(
    r'final\s+verdict\s*[:=]\s*(REAL\b|BENIGN\b|LIKELY[_\s]+REAL\b|UNCERTAIN\b)',
    re.IGNORECASE,
)


def _parse_cot_verdict(cot: Optional[str]) -> Optional[str]:
    """Extract 'REAL', 'BENIGN', or 'UNCERTAIN' from the LLM's CoT scratchpad."""
    if not cot:
        return None
    m = _RE_FINAL_VERDICT.search(str(cot))
    if not m:
        return None
    raw = m.group(1).upper().replace(' ', '_')
    if 'REAL' in raw:
        return 'REAL'
    if 'BENIGN' in raw:
        return 'BENIGN'
    return 'UNCERTAIN'


# ── Main verdict logic ────────────────────────────────────────────────────────

_SEV_WEIGHT = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}


def _has_observed_impact(prefill: dict) -> bool:
    impact = prefill.get('observed_impact') or {}
    if not isinstance(impact, dict):
        return False
    joined = ' '.join(str(v or '') for v in impact.values()).lower()
    if not joined.strip():
        return False
    negative = (
        'no confirmed', 'no named', 'no data loss', 'not observed',
        'depends on', 'requires investigation',
    )
    if any(token in joined for token in negative):
        return False
    positive = (
        'wire-transfer', 'wire transfer', 'payment', 'approval', 'mailbox access',
        'email-read', 'emails accessed', 'ransomware', 'exfiltration', 'executed',
    )
    return any(token in joined for token in positive)


def compute_cluster_verdict(cluster: dict) -> dict:
    """Return {'verdict': str, 'verdict_rationale': str, 'verdict_confidence': float}.

    This is purely deterministic — no LLM calls. Call it after tier1_prefill
    is attached so the CoT data is available.
    """
    prefill: dict = cluster.get('tier1_prefill') or {}
    cm: dict = cluster.get('confidence_meter') or prefill.get('confidence_meter') or {}
    confidence_total: float = float(cm.get('total') or 0.0)
    severity: str = str(cluster.get('severity') or '').lower()
    sev_weight: int = _SEV_WEIGHT.get(severity, 1)

    # Parse LLM CoT for explicit verdict signal
    cot_verdict = _parse_cot_verdict(prefill.get('_cot'))
    observed_impact = _has_observed_impact(prefill)

    # Gather supporting rationale text
    verdict_reasoning: str = str(prefill.get('verdict_reasoning') or '').strip()
    confidence_rationale = prefill.get('confidence_rationale') or []
    reason_summary: str = str(cluster.get('reason_summary') or '').strip()

    # Derive verdict label
    verdict: str
    if cot_verdict == 'BENIGN':
        verdict = 'BENIGN_EXPECTED'
    elif cot_verdict == 'REAL' and confidence_total >= 80 and sev_weight >= 4 and observed_impact:
        verdict = 'VALIDATED_BREACH'
    elif cot_verdict == 'REAL' and confidence_total >= 60:
        verdict = 'CONFIRMED_INTRUSION'
    elif cot_verdict == 'REAL' or confidence_total >= 40:
        verdict = 'LIKELY_COMPROMISE'
    elif confidence_total >= 20:
        verdict = 'SUSPICIOUS_ACTIVITY'
    elif confidence_total > 0:
        verdict = 'INSUFFICIENT_TELEMETRY'
    elif sev_weight >= 4:
        # No prefill yet — use severity as minimum signal
        verdict = 'LIKELY_COMPROMISE'
    elif sev_weight >= 3:
        verdict = 'SUSPICIOUS_ACTIVITY'
    else:
        verdict = 'SUSPICIOUS_ACTIVITY'

    # Build a short rationale string
    parts: list[str] = []
    if verdict_reasoning:
        parts.append(verdict_reasoning)
    elif confidence_rationale and isinstance(confidence_rationale, list):
        parts.append(' '.join(str(x) for x in confidence_rationale[:2]))
    elif reason_summary:
        parts.append(reason_summary[:200])

    if confidence_total > 0:
        parts.append(f'Confidence score: {confidence_total:.0f}/100.')
    if cot_verdict:
        parts.append(f'LLM adversarial check: {cot_verdict}.')

    rationale = ' '.join(parts).strip() or f'{severity.title()} severity cluster.'

    return {
        'verdict': verdict,
        'verdict_rationale': rationale,
        'verdict_confidence': round(confidence_total / 100.0, 3),
    }


# ── Batch retroactive backfill ────────────────────────────────────────────────

def backfill_cluster_verdicts(assessment: dict) -> int:
    """Attach verdict fields to any cluster that has tier1_prefill but no verdict.

    Returns count of clusters updated. Mutates assessment in-place.
    Safe to call repeatedly — skips clusters that already have a non-empty verdict.
    """
    clusters = assessment.get('correlation_clusters') or []
    updated = 0
    for cluster in clusters:
        existing = cluster.get('verdict') or ''
        if existing and existing not in ('UNCERTAIN', 'MISSING', ''):
            continue
        # Always derive a verdict if we have at least a severity field
        if not cluster.get('severity'):
            continue
        result = compute_cluster_verdict(cluster)
        cluster['verdict'] = result['verdict']
        cluster['verdict_rationale'] = result['verdict_rationale']
        cluster['verdict_confidence'] = result['verdict_confidence']
        updated += 1

    # If any clusters were updated, invalidate the stale exec summary cache
    # so the next page load rebuilds it with correct verdict counts.
    if updated:
        assessment.pop('exec_summary_llm', None)

    return updated
