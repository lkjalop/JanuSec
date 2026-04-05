from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule


@register_rule(name='email_phish_attachment_enriched', mitre=['T1204.002'], factors_required=['attachments','from_address'], window_seconds=86400, severity='medium', confidence_boost=0.2)
def email_phish_attachment_enriched(event: Dict[str, Any]) -> bool:
    attachments = event.get('attachments') or []
    frm = str(event.get('from_address') or '').lower()
    score = 0.1

    for a in attachments:
        name = str(a.get('filename') or '').lower()
        if name.endswith(('.docm', '.xlsm', '.pptm')):
            score += 0.35
        if any(k in name for k in ('invoice', 'payment', 'bank')):
            score += 0.15

    # executable attachments raise score
    if any(a.get('mimetype') == 'application/x-msdownload' for a in attachments):
        score += 0.3

    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({
            'rule': 'email_phish_attachment_enriched',
            'mitre': ['T1204.002'],
            'computed_score': round(min(score, 0.99), 3),
            'evidence': {'attachment_count': len(attachments), 'from': frm},
        })
    except Exception:
        pass

    return score >= 0.4
