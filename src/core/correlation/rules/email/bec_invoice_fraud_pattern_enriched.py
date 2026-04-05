from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule


@register_rule(name='bec_invoice_fraud_pattern_enriched', mitre=['T1598'], factors_required=['subject','attachments','indicators'], window_seconds=86400, severity='high', confidence_boost=0.45)
def bec_invoice_fraud_pattern_enriched(event: Dict[str, Any]) -> bool:
    subj = str(event.get('subject') or '').lower()
    atts = event.get('attachments') or []
    inds = event.get('indicators') or {}
    score = 0.2

    try:
        if any(k in subj for k in ('invoice','payment','bank','account change','wire')):
            score += 0.3
        if any((a.get('filename') or '').lower().endswith(('.pdf','.docx','.xlsx','invoice.pdf','invoice.docm')) for a in atts):
            score += 0.2
        if inds.get('urgency_language'):
            score += 0.15
        if inds.get('new_sender_domain') or inds.get('reply_to_mismatch'):
            score += 0.15
    except Exception:
        pass

    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({
            'rule': 'bec_invoice_fraud_pattern_enriched',
            'mitre': ['T1598'],
            'stride': ['Spoofing','Tampering'],
            'dread': {'score': 7},
            'maestro': {'tags': ['social_engineering','bec']},
            'diamond': {'adversary': 'unknown', 'capability': ['business_email_compromise']},
            'evidence': {
                'subject': subj,
                'attachments': [a.get('filename') for a in atts],
                'indicators': inds,
            },
        })
    except Exception:
        pass

    return score >= 0.6
