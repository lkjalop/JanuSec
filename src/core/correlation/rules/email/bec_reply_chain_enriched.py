from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule


@register_rule(name='bec_reply_chain_enriched', mitre=['T1598','T1204'], factors_required=['thread_context','attachments','indicators'], window_seconds=86400, severity='high', confidence_boost=0.45)
def bec_reply_chain_enriched(event: Dict[str, Any]) -> bool:
    tc = event.get('thread_context') or {}
    atts = event.get('attachments') or []
    inds = event.get('indicators') or {}
    score = 0.2

    try:
        replies = tc.get('recent_replies') or []
        chain = tc.get('reply_chain') or []
        participants = tc.get('participants') or []
        # urgency and reply-to mismatch are strong signals
        if bool(inds.get('urgency_language')):
            score += 0.2
        if bool(inds.get('reply_to_mismatch')):
            score += 0.2
        # vendor spoof: reply chain flips domains mid-thread
        vendor_spoof = False
        for hop in chain:
            try:
                fd = str((hop or {}).get('from_domain') or '').lower()
                rd = str((hop or {}).get('reply_to_domain') or '').lower()
                if fd and rd and fd != rd:
                    vendor_spoof = True
                    break
            except Exception:
                continue
        if vendor_spoof:
            score += 0.2
        # macro or payment-related attachment
        if any((a.get('filename') or '').lower().endswith(('.docm','.xlsm','.pptm')) for a in atts):
            score += 0.2
        if any(('invoice' in (a.get('filename','').lower()) or 'payment' in (a.get('filename','').lower())) for a in atts):
            score += 0.1
        # presence of executive + finance in participants and payment instruction in replies
        if any('ceo' in (p or '').lower() for p in participants) and any('finance' in (p or '').lower() for p in participants):
            if any(('wire' in str(x).lower() or 'invoice' in str(x).lower() or 'bank' in str(x).lower()) for x in replies):
                score += 0.2
    except Exception:
        pass

    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({
            'rule': 'bec_reply_chain_enriched',
            'mitre': ['T1598','T1204'],
            'stride': ['Spoofing','Tampering'],
            'dread': {'score': 7},
            'maestro': {'tags': ['social_engineering','bec']},
            'diamond': {'adversary': 'unknown', 'capability': ['business_email_compromise']},
            'evidence': {
                'participants': participants,
                'recent_replies': replies,
                'attachments': [a.get('filename') for a in atts],
                'indicators': inds,
                'vendor_spoof': vendor_spoof,
            },
        })
    except Exception:
        pass

    return score >= 0.6
