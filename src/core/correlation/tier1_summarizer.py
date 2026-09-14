from __future__ import annotations
from typing import Dict, Any, List


def summarize_tier1(event: Dict[str, Any]) -> Dict[str, Any]:
    """Deterministic Tier-1 summarizer.

    Consumes `event['correlation_emission']` and optional `event['factors']`.
    Returns a compact JSON-friendly summary suitable for analyst triage.
    """
    emission = event.get('correlation_emission') or {}
    factors = event.get('factors') or []

    verdict = str(
        event.get('verdict')
        or emission.get('verdict')
        or event.get('classification')
        or 'UNKNOWN'
    ).upper()
    confidence = event.get('confidence')
    if confidence is None:
        confidence = emission.get('computed_score') or 0.0
    next_actions = event.get('next_actions') or []
    if not next_actions:
        next_actions = [
            'Review correlated evidence and validate the impacted identity or resource.',
            'Confirm whether the activity matches expected Azure administrative behavior.',
            'Escalate for analyst approval if the activity changes privileges or impacts production resources.',
        ]

    summary: Dict[str, Any] = {
        'title': emission.get('rule') or 'unknown',
        'score': float(emission.get('computed_score') or 0.0),
        'verdict': verdict,
        'confidence': float(confidence or 0.0),
        'mitre': emission.get('mitre') or [],
        'attack_tags': emission.get('mitre') or [],
        'reason': [],
        'top_factors': [],
        'evidence_summary': '',
        'next_actions': list(next_actions)[:3],
    }

    evidence = emission.get('evidence') or {}
    # deterministic reason strings
    if evidence:
        for k in sorted(evidence.keys()):
            v = evidence[k]
            summary['reason'].append(f"{k}={truncate_for_reason(v)}")

    # populate top_factors from 'factors' (list of dicts with score)
    try:
        sorted_factors = sorted(factors, key=lambda x: x.get('score', 0), reverse=True)[:5]
        for f in sorted_factors:
            summary['top_factors'].append({'name': f.get('name'), 'score': float(f.get('score', 0))})
    except Exception:
        pass

    if summary['reason']:
        summary['evidence_summary'] = '; '.join(summary['reason'][:3])
    elif summary['top_factors']:
        summary['evidence_summary'] = '; '.join(
            f"{entry.get('name')}={entry.get('score')}" for entry in summary['top_factors'][:3]
        )
    else:
        summary['evidence_summary'] = 'Deterministic Tier 1 summary generated with limited evidence.'

    # ensure deterministic ordering
    summary['mitre'] = sorted(summary['mitre'])
    summary['attack_tags'] = sorted(summary['attack_tags'])
    summary['reason'] = sorted(summary['reason'])

    return summary


def truncate_for_reason(v: Any, maxlen: int = 80) -> str:
    s = str(v)
    if len(s) > maxlen:
        return s[:maxlen-3] + '...'
    return s
