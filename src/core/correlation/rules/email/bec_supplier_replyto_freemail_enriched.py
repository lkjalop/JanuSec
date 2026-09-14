from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule


@register_rule(name='bec_supplier_replyto_freemail_enriched', mitre=['T1598'],
               factors_required=['from','reply_to','indicators'], window_seconds=86400,
               severity='high', confidence_boost=0.45)
def bec_supplier_replyto_freemail_enriched(event: Dict[str, Any]) -> bool:
    frm = str(event.get('from') or '').lower()
    reply = str(event.get('reply_to') or '').lower()
    inds = event.get('indicators') or {}
    score = 0.2

    try:
        # If reply-to is free-mail provider and differs from from domain
        free_domains = ('gmail.com','yahoo.com','outlook.com','hotmail.com','proton.me','protonmail.com')
        reply_domain = reply.split('@')[-1] if '@' in reply else ''
        from_domain = frm.split('@')[-1] if '@' in frm else ''
        if reply_domain and reply_domain in free_domains and reply_domain != from_domain:
            score += 0.4
        if inds.get('brand_mismatch') or inds.get('reply_to_mismatch'):
            score += 0.15
        if event.get('links'):
            score += 0.1
    except Exception:
        pass

    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({
            'rule': 'bec_supplier_replyto_freemail_enriched',
            'mitre': ['T1598'],
            'stride': ['Spoofing'],
            'dread': {'score': 8},
            'maestro': {'tags': ['social_engineering','reply_to_freemail']},
            'evidence': {'from_domain': from_domain, 'reply_domain': reply_domain, 'indicators': inds}
        })
    except Exception:
        pass

    return score >= 0.6
