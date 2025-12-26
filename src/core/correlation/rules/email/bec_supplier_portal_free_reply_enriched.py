from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule


@register_rule(name='bec_supplier_portal_free_reply_enriched', mitre=['T1598'],
               factors_required=['subject','links','indicators','reply_to'], window_seconds=86400,
               severity='high', confidence_boost=0.45)
def bec_supplier_portal_free_reply_enriched(event: Dict[str, Any]) -> bool:
    subj = str(event.get('subject') or '').lower()
    links = event.get('links') or []
    inds = event.get('indicators') or {}
    reply_to = str(event.get('reply_to') or '').lower()
    score = 0.2

    try:
        # Reply-to uses free mail domains (gmail, yahoo, outlook)
        if reply_to and any(d in reply_to for d in ('@gmail.com','@hotmail.com','@yahoo.com','@outlook.com','@protonmail.com')):
            score += 0.3
        # Subject/vendor keywords
        if any(k in subj for k in ('supplier','vendor','portal','payment','invoice','account')):
            score += 0.15
        # New link domains not equal to known vendor domain
        for l in links:
            d = str(l.get('domain') or '').lower()
            if d and inds.get('new_sender_domain'):
                score += 0.1
        if inds.get('reply_to_mismatch'):
            score += 0.1
    except Exception:
        pass

    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({
            'rule': 'bec_supplier_portal_free_reply_enriched',
            'mitre': ['T1598'],
            'stride': ['Spoofing','Tampering'],
            'dread': {'score': 7},
            'maestro': {'tags': ['social_engineering','supplier_portal']},
            'evidence': {
                'subject': subj,
                'reply_to': reply_to,
                'links': [{'domain': l.get('domain')} for l in links],
                'indicators': inds,
            }
        })
    except Exception:
        pass

    return score >= 0.6
