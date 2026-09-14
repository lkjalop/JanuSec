from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule


@register_rule(name='email_social_engineering_text_enriched', mitre=['T1592'], factors_required=['body','from_address'], window_seconds=86400, severity='low', confidence_boost=0.1)
def email_social_engineering_text_enriched(event: Dict[str, Any]) -> bool:
    body = (event.get('body') or '').lower()
    frm = (event.get('from_address') or '').lower()
    score = 0.05

    if not body or not frm:
        return False

    phishing_phrases = ('confirm your account', 'reset your password', 'verify your identity', 'wire the funds', 'urgent action required')
    if any(p in body for p in phishing_phrases):
        score += 0.4

    if 'click here' in body or 'login below' in body:
        score += 0.2

    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({
            'rule': 'email_social_engineering_text_enriched',
            'mitre': ['T1592'],
            'computed_score': round(min(score, 0.95), 3),
            'evidence': {'from': frm, 'snippet': body[:200]},
        })
    except Exception:
        pass

    return score >= 0.35
