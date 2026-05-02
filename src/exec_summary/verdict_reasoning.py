"""Verdict reasoning — re-derives and explains the verdict from evidence.

This is what makes a CEO trust the summary. Instead of just propagating
the cluster's pre-assigned verdict, this module:

1. Runs the cluster grader to get sufficiency/coherence/fp_risk scores
2. Classifies individual rows via event_disposition to find counter-hypotheses
3. Produces a structured reasoning chain that either confirms or weakens the verdict

The output is a deterministic, auditable "show your work" block.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


def derive_verdict_reasoning(
    cluster: dict,
    rows: list[dict],
    assessment: Optional[dict] = None,
) -> dict:
    """Re-derive verdict reasoning from evidence for a single cluster.

    Returns dict with:
        grader_verdict: str — ACCEPT/REFINE/REJECT from the grader
        composite_score: float — 0-1 composite
        sufficiency: float
        coherence: float
        fp_risk: float
        grader_reasons: list[str]
        grader_caveats: list[str]
        disposition_breakdown: dict — counts by disposition category
        counter_hypotheses: list[str] — why this might NOT be a breach
        confirming_evidence: list[str] — why this IS a breach
        verdict_confidence_sentence: str — one-liner for the CEO
        evidence_quality: str — 'strong'/'moderate'/'weak'
    """
    result: dict[str, Any] = {
        'grader_verdict': '',
        'composite_score': 0.0,
        'sufficiency': 0.0,
        'coherence': 0.0,
        'fp_risk': 0.0,
        'grader_reasons': [],
        'grader_caveats': [],
        'disposition_breakdown': {},
        'counter_hypotheses': [],
        'confirming_evidence': [],
        'verdict_confidence_sentence': '',
        'evidence_quality': 'weak',
    }

    # ── Step 1: Cluster grader ────────────────────────────────────────────
    try:
        from src.analysis.cluster_grader import grade_cluster
        grade = grade_cluster(cluster)
        result['grader_verdict'] = grade.get('verdict', '')
        result['composite_score'] = grade.get('composite', 0.0)
        result['sufficiency'] = grade.get('sufficiency', 0.0)
        result['coherence'] = grade.get('coherence', 0.0)
        result['fp_risk'] = grade.get('fp_risk', 0.0)
        result['grader_reasons'] = grade.get('reasons', [])
        result['grader_caveats'] = grade.get('caveats', [])
    except Exception as exc:
        logger.debug('cluster grader failed: %s', exc)

    # ── Step 2: Event disposition on individual rows ──────────────────────
    disposition_counts: dict[str, int] = {}
    counter_hypotheses: list[str] = []
    confirming_evidence: list[str] = []

    try:
        from src.analysis.event_disposition import classify as classify_event
        for row in rows[:50]:  # Cap to avoid over-processing
            factors = _extract_factors(row)
            if not factors:
                continue
            try:
                dr = classify_event(
                    factors=factors,
                    verdict=str(row.get('verdict') or row.get('severity') or ''),
                    triage_score=float(row.get('triage_score') or 0),
                    user=str(row.get('user') or row.get('entity') or ''),
                )
                disp = dr.disposition.value
                disposition_counts[disp] = disposition_counts.get(disp, 0) + 1

                # Accumulate counter-hypotheses (non-attack dispositions)
                if disp in ('false_positive', 'human_behavior', 'red_team'):
                    if dr.evidence_sentence and len(counter_hypotheses) < 5:
                        counter_hypotheses.append(dr.evidence_sentence)
                elif disp == 'confirmed_attack':
                    if dr.evidence_sentence and len(confirming_evidence) < 5:
                        confirming_evidence.append(dr.evidence_sentence)
            except Exception:
                continue
    except Exception as exc:
        logger.debug('event disposition classification failed: %s', exc)

    result['disposition_breakdown'] = disposition_counts
    result['counter_hypotheses'] = counter_hypotheses
    result['confirming_evidence'] = confirming_evidence

    # ── Step 3: Synthesize verdict confidence sentence ────────────────────
    total_classified = sum(disposition_counts.values())
    n_attack = disposition_counts.get('confirmed_attack', 0)
    n_fp = disposition_counts.get('false_positive', 0)
    n_human = disposition_counts.get('human_behavior', 0)
    n_gray = disposition_counts.get('gray_area', 0)
    composite = result['composite_score']

    # Evidence quality assessment
    if composite >= 0.72 and n_attack > n_fp:
        result['evidence_quality'] = 'strong'
    elif composite >= 0.45:
        result['evidence_quality'] = 'moderate'
    else:
        result['evidence_quality'] = 'weak'

    # Build the one-liner that directly addresses "was there a breach?"
    cluster_verdict = str(
        cluster.get('verdict') or cluster.get('final_verdict') or 'UNCERTAIN'
    ).upper()
    parts: list[str] = []

    if cluster_verdict in ('CONFIRMED_BREACH', 'VALIDATED_BREACH', 'LIKELY_BREACH',
                           'CONFIRMED_INTRUSION', 'LIKELY_COMPROMISE'):
        if result['evidence_quality'] == 'strong':
            parts.append(
                f'Verdict CONFIRMED with {result["evidence_quality"]} evidence'
                f' (composite score {composite:.0%}).'
            )
        elif result['evidence_quality'] == 'moderate':
            parts.append(
                f'Verdict {cluster_verdict} is supported but has gaps'
                f' (composite {composite:.0%}).'
            )
        else:
            parts.append(
                f'Verdict {cluster_verdict} rests on weak evidence'
                f' (composite {composite:.0%}) — requires analyst confirmation.'
            )
    else:
        if n_attack == 0 and total_classified > 0:
            parts.append(
                f'No confirmed attack signals in {total_classified} classified rows.'
            )
        elif n_attack > 0:
            parts.append(
                f'{n_attack} attack signals found but verdict remains {cluster_verdict}.'
            )
        else:
            parts.append(f'Verdict: {cluster_verdict} (no disposition data available).')

    # Counter-hypothesis summary
    if n_fp > 0:
        parts.append(f'{n_fp} row{"s" if n_fp > 1 else ""} classified as likely false positive.')
    if n_human > 0:
        parts.append(f'{n_human} row{"s" if n_human > 1 else ""} attributed to human behavior, not external attack.')
    if n_gray > 0:
        parts.append(f'{n_gray} borderline row{"s" if n_gray > 1 else ""} requiring analyst judgment.')

    # Grader caveats
    caveats = result['grader_caveats']
    if caveats:
        parts.append(f'Caveats: {caveats[0]}')

    result['verdict_confidence_sentence'] = ' '.join(parts)
    return result


def _extract_factors(row: dict) -> list[str]:
    """Extract factor strings from a normalized row."""
    factors: list[str] = []
    # Direct factor field
    raw = row.get('factors') or row.get('factor') or row.get('tags') or []
    if isinstance(raw, list):
        factors.extend(str(f) for f in raw if f)
    elif isinstance(raw, str) and raw:
        factors.append(raw)

    # Infer from description/event_type and Santos-specific fields
    # event_simpleName is the CrowdStrike/Falcon field name used in Santos endpoint data
    desc = str(
        row.get('description')
        or row.get('event_type')
        or row.get('event_simpleName')
        or row.get('event_name')
        or row.get('action')
        or ''
    ).lower()
    if desc:
        # Map common description patterns to factor signals
        _patterns = {
            'brute': 'brute_force',
            'credential': 'credential_access',
            'exfil': 'data_exfiltration',
            'rclone': 'data_exfiltration',
            'lsass': 'credential_access',
            'mimikatz': 'credential_access',
            'certutil': 'defense_evasion',
            'kerberoast': 'credential_access',
            'lateral': 'lateral_movement',
            'privilege': 'privilege_escalation',
            'assumerole': 'privilege_escalation',
            'daemonset': 'container_escape',
            'hostpid': 'container_escape',
            'phish': 'phishing',
            'malware': 'malware_execution',
            'c2': 'command_and_control',
            'beacon': 'command_and_control',
            'login fail': 'failed_authentication',
            'login_fail': 'failed_authentication',
            'impossible travel': 'impossible_travel',
        }
        for pattern, factor in _patterns.items():
            if pattern in desc:
                factors.append(factor)

    return factors
