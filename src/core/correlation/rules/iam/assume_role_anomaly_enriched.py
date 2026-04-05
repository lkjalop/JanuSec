from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule

@register_rule(name='iam_assume_role_anomaly_enriched', mitre=['T1078','T1098'], factors_required=['assume_role','user'], window_seconds=1800, severity='high', confidence_boost=0.4)
def iam_assume_role_anomaly_enriched(event: Dict[str, Any]) -> bool:
    """Detect anomalous AssumeRole activity (unusual source or burst).

    Fires when event indicates AWS `AssumeRole` with unusual source IP/agent or
    explicit anomaly flags like `assume_role_anomaly`, emitting explainability info.
    """
    domain = (event.get('domain') or '').lower()
    ev_name = (event.get('eventName') or '').lower()
    src = (event.get('sourceIp') or event.get('sourceIPAddress') or '').lower()
    agent = (event.get('userAgent') or '').lower()
    anomaly = bool(event.get('assume_role_anomaly'))

    is_assume_role = 'assumerole' in ev_name
    src_unusual = any(x in src for x in ['tor', 'vpn', 'unknown']) or 'curl' in agent

    fired = (domain == 'iam' and is_assume_role and (anomaly or src_unusual))

    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({
            'rule': 'iam_assume_role_anomaly_enriched',
            'mitre': ['T1078','T1098'],
            'evidence': {
                'eventName': ev_name,
                'sourceIp': src,
                'userAgent': agent,
                'anomaly_flag': anomaly,
            },
        })
    except Exception:
        pass

    return bool(fired)
