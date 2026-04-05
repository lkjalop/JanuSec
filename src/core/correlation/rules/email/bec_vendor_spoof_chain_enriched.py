from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule


@register_rule(name='bec_vendor_spoof_chain_enriched', mitre=['T1598','T1204'], factors_required=['thread_context','indicators'], window_seconds=86400, severity='high', confidence_boost=0.45)
def bec_vendor_spoof_chain_enriched(event: Dict[str, Any]) -> bool:
    tc = event.get('thread_context') or {}
    inds = event.get('indicators') or {}
    score = 0.2

    try:
        chain = tc.get('reply_chain') or []
        vendor_domains = set()
        mismatch_hops = 0
        for hop in chain:
            try:
                fd = str((hop or {}).get('from_domain') or '').lower()
                rd = str((hop or {}).get('reply_to_domain') or '').lower()
                if fd:
                    vendor_domains.add(fd)
                if rd and fd and rd != fd:
                    mismatch_hops += 1
            except Exception:
                continue
        if mismatch_hops >= 1:
            score += 0.3
        if len(vendor_domains) >= 2:
            score += 0.2
        if inds.get('display_name_mismatch'):
            score += 0.1
        if inds.get('new_sender_domain'):
            score += 0.1
    except Exception:
        pass

    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({
            'rule': 'bec_vendor_spoof_chain_enriched',
            'mitre': ['T1598','T1204'],
            'stride': ['Spoofing','Tampering'],
            'dread': {'score': 7},
            'maestro': {'tags': ['social_engineering','bec']},
            'diamond': {'adversary': 'unknown', 'capability': ['business_email_compromise']},
            'evidence': {
                'vendor_domains': sorted(list(vendor_domains)) if 'vendor_domains' in locals() else [],
                'mismatch_hops': mismatch_hops if 'mismatch_hops' in locals() else 0,
                'indicators': inds,
            },
        })
    except Exception:
        pass

    return score >= 0.6
