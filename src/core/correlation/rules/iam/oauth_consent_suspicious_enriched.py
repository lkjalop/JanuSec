from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule

@register_rule(name='iam_oauth_consent_suspicious_enriched', mitre=['T1556','T1193'], factors_required=['oauth_consent','user'], window_seconds=1800, severity='high', confidence_boost=0.45)
def iam_oauth_consent_suspicious_enriched(event: Dict[str, Any]) -> bool:
    """Flag suspicious OAuth consent events (e.g., risky app grant).

    Fires when the event indicates an OAuth consent pattern with unusual app/vendor
    or when an explicit `oauth_consent_suspicious` flag is present. Adds structured
    `correlation_emission` for explainability.
    """
    domain = (event.get('domain') or '').lower()
    suspicious_flag = bool(event.get('oauth_consent_suspicious'))
    method = (event.get('methodName') or event.get('eventName') or '').lower()
    app = (event.get('application') or event.get('appName') or '').lower()
    vendor = (event.get('vendor') or '').lower()

    is_oauth = ('consent' in method) or ('oauth' in method) or ('oauth' in app)
    risky_vendor = any(x in vendor for x in ['unknown', 'thirdparty', 'unverified'])

    fired = (domain == 'iam' and (suspicious_flag or (is_oauth and risky_vendor)))

    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({
            'rule': 'iam_oauth_consent_suspicious_enriched',
            'mitre': ['T1556','T1193'],
            'evidence': {
                'domain': domain,
                'method': method,
                'app': app,
                'vendor': vendor,
                'suspicious_flag': suspicious_flag,
            },
        })
    except Exception:
        pass

    return bool(fired)
