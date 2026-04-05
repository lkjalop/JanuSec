from typing import List, Dict, Any
from ..canonical_event import CanonicalEvent

class FactorEmit(dict):
    pass

def extract_email_factors(events: List[CanonicalEvent]) -> List[FactorEmit]:
    out: List[FactorEmit] = []
    for e in events:
        if e.source_type != 'email':
            continue
        # suspicious_sender_domain heuristic
        if e.user and e.user.endswith('.ru'):
            out.append(FactorEmit(name='suspicious_sender_domain', nodes=[f"host:{e.user}"], domain='email', confidence=0.7, ts=e.timestamp))
        # attachment_macro
        if e.attachment_type and e.attachment_type.lower() in {'docm','xlsm','pptm','vbs'}:
            out.append(FactorEmit(name='attachment_macro', nodes=[f"file_hash:{e.file_hash}" if e.file_hash else 'file:unknown'], domain='email', confidence=0.6, ts=e.timestamp))
        # SPF_fail (simplified: presence of tag)
        if 'spf_fail' in e.threat_tags:
            out.append(FactorEmit(name='SPF_fail', nodes=[f"host:{e.user}"], domain='email', confidence=0.55, ts=e.timestamp))
        # url_shortener_risk (simplified: subject contains shortened URL keyword)
        if e.subject and 'bit.ly' in e.subject.lower():
            out.append(FactorEmit(name='url_shortener_risk', nodes=['domain:bit.ly'], domain='email', confidence=0.5, ts=e.timestamp))
        # mailbox_forward_rule_added (simplified tag)
        if 'forward_rule_added' in e.threat_tags:
            out.append(FactorEmit(name='mailbox_forward_rule_added', nodes=[f"mailbox:{e.mailbox or 'unknown'}"], domain='email', confidence=0.65, ts=e.timestamp))
    return out
