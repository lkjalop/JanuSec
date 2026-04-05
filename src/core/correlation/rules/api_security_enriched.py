from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule


@register_rule(name='api_bola_enriched', mitre=['T1531'], factors_required=['parsed_request','client_ip'], window_seconds=300, severity='high', confidence_boost=0.45)
def api_bola_enriched(event: Dict[str, Any]) -> bool:
    parsed = event.get('parsed_request') or {}
    uri = str(parsed.get('uri') or '')
    auth_user = str(parsed.get('auth_user') or '')
    # Heuristic: if uri contains /users/<id>/ and body has different user_id, flag
    import re
    m = re.search(r'/users/(\d+)', uri)
    if m:
        body_user = str((parsed.get('body') or {}).get('user_id') or '')
        if body_user and body_user != auth_user:
            score = 0.6
            try:
                event.setdefault('correlation_emission', {})
                event['correlation_emission'].update({
                    'rule': 'api_bola_enriched',
                    'mitre': ['T1531'],
                    'computed_score': round(score, 3),
                    'evidence': {'uri': uri, 'auth_user': auth_user, 'body_user': body_user},
                })
            except Exception:
                pass
            return True
    return False
