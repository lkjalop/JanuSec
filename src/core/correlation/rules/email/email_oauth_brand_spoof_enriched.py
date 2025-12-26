from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule


@register_rule(name='email_oauth_brand_spoof_enriched', mitre=['T1598','T1193'],
               factors_required=['subject','links','indicators'], window_seconds=86400,
               severity='high', confidence_boost=0.45)
def email_oauth_brand_spoof_enriched(event: Dict[str, Any]) -> bool:
    subj = str(event.get('subject') or '').lower()
    links = event.get('links') or []
    inds = event.get('indicators') or {}
    score = 0.2

    try:
        # OAuth/login related keywords
        if any(k in subj for k in ('login', 'reauthorize', 'sign in', 'authorize', 'oauth', 'authenticate')):
            score += 0.25
        # Links leading to known oauth providers but with mismatched domains
        for l in links:
            d = str(l.get('domain') or '').lower()
            if d and any(p in d for p in ('accounts.google', 'login.microsoft', 'login.live', 'appleid.apple')) and inds.get('domain_mismatch'):
                score += 0.25
        # Presence of oauth redirect parameters or base64 encoded JWT-like tokens in url
        if any(l.get('url') and ('redirect_uri=' in (l.get('url') or '') or 'token=' in (l.get('url') or '')) for l in links):
            score += 0.1
        if inds.get('brand_mismatch'):
            score += 0.1
    except Exception:
        pass

    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({
            'rule': 'email_oauth_brand_spoof_enriched',
            'mitre': ['T1598','T1193'],
            'stride': ['Spoofing','Tampering'],
            'dread': {'score': 8},
            'maestro': {'tags': ['social_engineering','oauth_spoof']},
            'diamond': {'adversary': 'unknown', 'capability': ['account_takeover']},
            'evidence': {
                'subject': subj,
                'links': [{'domain': l.get('domain'), 'url': l.get('url')} for l in links],
                'indicators': inds,
            }
        })
    except Exception:
        pass

    return score >= 0.6
