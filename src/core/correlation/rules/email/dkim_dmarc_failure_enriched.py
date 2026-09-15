from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule


@register_rule(name='email_dkim_dmarc_failure_enriched', mitre=['T1598'], factors_required=['spf_result','dkim_result','dmarc_result'], window_seconds=86400, severity='medium', confidence_boost=0.3)
def email_dkim_dmarc_failure_enriched(event: Dict[str, Any]) -> bool:
    spf = event.get('spf_result')
    dkim = event.get('dkim_result')
    dmarc = event.get('dmarc_result')
    score = 0.0

    if spf == 'fail':
        score += 0.3
    if dkim == 'fail':
        score += 0.35
    if dmarc == 'fail':
        score += 0.4

    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({
            'rule': 'email_dkim_dmarc_failure_enriched',
            'mitre': ['T1598'],
            'computed_score': round(min(score, 0.99), 3),
            'evidence': {'spf': spf, 'dkim': dkim, 'dmarc': dmarc},
        })
    except Exception:
        pass

    return score >= 0.5
