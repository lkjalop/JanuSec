from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule


@register_rule(name='bec_payment_change_dkim_flip_enriched', mitre=['T1598'],
               factors_required=['subject','attachments','indicators','dkim_status'], window_seconds=86400,
               severity='high', confidence_boost=0.45)
def bec_payment_change_dkim_flip_enriched(event: Dict[str, Any]) -> bool:
    subj = str(event.get('subject') or '').lower()
    atts = event.get('attachments') or []
    inds = event.get('indicators') or {}
    dkim = str(event.get('dkim_status') or '').lower()
    score = 0.2

    try:
        if any(k in subj for k in ('payment','invoice','bank','account change','wire')):
            score += 0.25
        # Attachments often invoice/bank documents
        if any((a.get('filename') or '').lower().endswith(('.pdf','.xlsx','.docx')) for a in atts):
            score += 0.15
        # DKIM pass but domain flip between From and d= value indicates forged forwarding chain
        if dkim == 'pass' and inds.get('from_domain_flip'):
            score += 0.3
        if inds.get('reply_to_mismatch'):
            score += 0.1
    except Exception:
        pass

    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({
            'rule': 'bec_payment_change_dkim_flip_enriched',
            'mitre': ['T1598'],
            'stride': ['Spoofing','Tampering'],
            'dread': {'score': 8},
            'maestro': {'tags': ['social_engineering','payment_fraud']},
            'evidence': {
                'subject': subj,
                'attachments': [a.get('filename') for a in atts],
                'dkim_status': dkim,
                'indicators': inds,
            }
        })
    except Exception:
        pass

    return score >= 0.7
