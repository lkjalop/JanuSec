from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule


@register_rule(name='bec_payment_change_dkim_pass_domain_flip_enriched', mitre=['T1598'],
               factors_required=['subject','dkim_result','thread_context','indicators'], window_seconds=86400,
               severity='high', confidence_boost=0.5)
def bec_payment_change_dkim_pass_domain_flip_enriched(event: Dict[str, Any]) -> bool:
    subj = str(event.get('subject') or '').lower()
    dkim = str(event.get('dkim_result') or '').lower()
    tc = event.get('thread_context') or {}
    inds = event.get('indicators') or {}
    score = 0.2

    try:
        if any(k in subj for k in ('payment','bank','wire','account change','update payment')):
            score += 0.25
        if dkim == 'pass':
            score += 0.2
        # Domain flip across reply chain (original vendor -> new domain)
        chain = tc.get('reply_chain') or []
        domains = set()
        for hop in chain:
            fd = str((hop or {}).get('from_domain') or '').lower()
            if fd:
                domains.add(fd)
        # current from domain
        cur_from = str(event.get('from_domain') or (event.get('from') or '').split('@')[-1]).lower()
        if cur_from and domains and cur_from not in domains:
            score += 0.25
        if inds.get('urgency_language'):
            score += 0.1
    except Exception:
        pass

    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({
            'rule': 'bec_payment_change_dkim_pass_domain_flip_enriched',
            'mitre': ['T1598'],
            'stride': ['Spoofing','Tampering'],
            'dread': {'score': 9},
            'maestro': {'tags': ['social_engineering','invoice_fraud','dkim_flip']},
            'evidence': {'subject': subj, 'dkim': dkim, 'reply_chain_domains': sorted(list(domains)), 'current_from': cur_from, 'indicators': inds}
        })
    except Exception:
        pass

    return score >= 0.7
