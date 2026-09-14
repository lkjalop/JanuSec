from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule


@register_rule(name='email_header_spoof_enriched', mitre=['T1598'], factors_required=['from_address','received_headers'], window_seconds=86400, severity='medium', confidence_boost=0.25)
def email_header_spoof_enriched(event: Dict[str, Any]) -> bool:
    frm = str(event.get('from_address') or '').lower()
    received = event.get('received_headers') or []
    score = 0.15

    if not frm or not received:
        return False

    # heuristic: mismatch between EHLO/HELO origin and from domain
    try:
        top_recv = str(received[0]).lower()
        if frm.split('@')[-1] not in top_recv:
            score += 0.3
    except Exception:
        pass

    # SPF/DMARC failures increase score if present
    if event.get('spf_result') == 'fail' or event.get('dmarc_result') == 'fail':
        score += 0.25

    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({
            'rule': 'email_header_spoof_enriched',
            'mitre': ['T1598'],
            'computed_score': round(min(score, 0.95), 3),
            'evidence': {'from': frm, 'top_received': received[0] if received else None, 'spf': event.get('spf_result'), 'dmarc': event.get('dmarc_result')},
        })
    except Exception:
        pass

    return score >= 0.5
