from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule


@register_rule(name='bec_supplier_portal_takeover_enriched', mitre=['T1598','T1204'],
               factors_required=['subject','indicators','links'], window_seconds=86400,
               severity='high', confidence_boost=0.45)
def bec_supplier_portal_takeover_enriched(event: Dict[str, Any]) -> bool:
    subj = str(event.get('subject') or '').lower()
    inds = event.get('indicators') or {}
    links = event.get('links') or []
    tc = event.get('thread_context') or {}
    score = 0.2

    try:
        # Supplier portal/payment portal/account update themes
        if any(k in subj for k in (
            'supplier', 'vendor', 'portal', 'payment portal', 'account update', 'update your account', 'login')):
            score += 0.25

        # Presence of login page/link indicators
        if inds.get('login_link_present') or any((l.get('type') == 'link' and l.get('domain')) for l in links):
            score += 0.15

        # Brand/reply-to/domain mismatches are strong signals
        if inds.get('brand_mismatch') or inds.get('reply_to_mismatch'):
            score += 0.15

        # New link domain not seen in vendor history (use thread_context vendor chain if available)
        new_link_domains = set()
        try:
            vendor_domains = set()
            for hop in (tc.get('reply_chain') or []):
                fd = str((hop or {}).get('from_domain') or '').lower()
                if fd:
                    vendor_domains.add(fd)
            for l in links:
                d = str(l.get('domain') or '').lower()
                if d and (d not in vendor_domains):
                    new_link_domains.add(d)
        except Exception:
            pass
        if new_link_domains:
            score += 0.2

        # Risky attachment types often used for portal phishing (HTML smuggling, etc.)
        atts = event.get('attachments') or []
        if any((a.get('filename') or '').lower().endswith(('.html', '.htm')) for a in atts):
            score += 0.1

        # Urgency/social-engineering language
        if inds.get('urgency_language'):
            score += 0.1
    except Exception:
        pass

    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({
            'rule': 'bec_supplier_portal_takeover_enriched',
            'mitre': ['T1598','T1204'],
            'stride': ['Spoofing','Tampering'],
            'dread': {'score': 7},
            'maestro': {'tags': ['social_engineering','bec']},
            'diamond': {'adversary': 'unknown', 'capability': ['business_email_compromise']},
            'evidence': {
                'subject': subj,
                'indicators': inds,
                'new_link_domains': sorted(list(new_link_domains)) if 'new_link_domains' in locals() else [],
                'links': [{'domain': l.get('domain')} for l in links if l.get('domain')],
            },
        })
    except Exception:
        pass

    return score >= 0.6
