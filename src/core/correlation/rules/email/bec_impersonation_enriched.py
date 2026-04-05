from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule


@register_rule(name='email_bec_impersonation_enriched', mitre=['T1598.002'], factors_required=['from_address','display_name','reply_to'], window_seconds=86400, severity='high', confidence_boost=0.5)
def email_bec_impersonation_enriched(event: Dict[str, Any]) -> bool:
    frm = str(event.get('from_address') or '').lower()
    display = str(event.get('display_name') or '').lower()
    reply_to = str(event.get('reply_to') or '').lower()
    score = 0.2

    if not frm:
        return False

    # display name contains a known executive pattern
    if any(tok in display for tok in ('ceo', 'cfo', 'chief', 'director', 'head')):
        score += 0.25

    # reply-to domain differs from from_address domain
    try:
        if reply_to and reply_to.split('@')[-1] != frm.split('@')[-1]:
            score += 0.25
    except Exception:
        pass

    # suspicious keywords
    subject = (event.get('subject') or '').lower()
    if any(k in subject for k in ('wire', 'invoice', 'payment', 'urgent')):
        score += 0.15

    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({
            'rule': 'email_bec_impersonation_enriched',
            'mitre': ['T1598.002'],
            'computed_score': round(min(score, 0.99), 3),
            'evidence': {'from': frm, 'display': display, 'reply_to': reply_to, 'subject': subject},
        })
    except Exception:
        pass

    return score >= 0.6
