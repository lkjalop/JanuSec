from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule


@register_rule(name='email_to_lolbin_chain_enriched', mitre=['T1204','T1546'], factors_required=['message_id','process_parent_message_id'], window_seconds=7200, severity='high', confidence_boost=0.35)
def email_to_lolbin_chain_enriched(event: Dict[str, Any]) -> bool:
    # heuristic: message_id ties an email attachment to a later process execution (parent_message_id)
    msg = event.get('message_id')
    parent_msg = event.get('process_parent_message_id')
    score = 0.0

    if msg and parent_msg and str(msg) == str(parent_msg):
        # presence of macro-enabled attachment increases score
        attachments = event.get('attachments') or []
        if any((a.get('filename') or '').lower().endswith(('.docm', '.xlsm', '.pptm')) for a in attachments):
            score += 0.5
        # if later process is a lolbin
        proc = (event.get('process_name') or '').lower()
        if proc in ('osascript','cron','at','nohup','launchctl','systemd-run'):
            score += 0.3

    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({
            'rule': 'email_to_lolbin_chain_enriched',
            'mitre': ['T1204','T1546'],
            'computed_score': round(min(score, 0.99), 3),
            'evidence': {'message_id': msg, 'proc': event.get('process_name'), 'attachments': [a.get('filename') for a in (event.get('attachments') or [])]},
        })
    except Exception:
        pass

    return score >= 0.6
