from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule


@register_rule(name='bec_brand_oauth_spoof_enriched', mitre=['T1598','T1204'],
               factors_required=['subject','links','indicators'], window_seconds=86400,
               severity='high', confidence_boost=0.45)
def bec_brand_oauth_spoof_enriched(event: Dict[str, Any]) -> bool:
    subj = str(event.get('subject') or '').lower()
    links = event.get('links') or []
    inds = event.get('indicators') or {}
    score = 0.2

    try:
        # Look for OAuth/login language or 'Sign in with' cues
        if any(k in subj for k in ('sign in','sign-in','oauth','authorize','login','authenticate')):
            score += 0.2
        # Links pointing to oauth login patterns or oauth providers
        oauth_like = any('oauth' in (l.get('url') or '').lower() or 'signin' in (l.get('url') or '').lower() for l in links)
        if oauth_like:
            score += 0.25
        # Display/account hints and brand mismatch
        if inds.get('brand_mismatch') or inds.get('reply_to_mismatch'):
            score += 0.15
        # New link domain not in vendor history
        new_domains = set()
        tc = event.get('thread_context') or {}
        vendor_domains = set((hop.get('from_domain') for hop in (tc.get('reply_chain') or []) if hop))
        for l in links:
            d = str(l.get('domain') or '').lower()
            if d and d not in vendor_domains:
                new_domains.add(d)
        if new_domains:
            score += 0.15
    except Exception:
        pass

    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({
            'rule': 'bec_brand_oauth_spoof_enriched',
            'mitre': ['T1598','T1204'],
            'stride': ['Spoofing','Tampering'],
            'dread': {'score': 8},
            'maestro': {'tags': ['social_engineering','oauth_spoof']},
            'diamond': {'adversary': 'unknown', 'capability': ['business_email_compromise']},
            'evidence': {'subject': subj, 'links': [l.get('url') for l in links], 'indicators': inds}
        })
    except Exception:
        pass

    return score >= 0.6
