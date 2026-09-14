from typing import List, Dict, Any
from ..canonical_event import CanonicalEvent

try:
    from src.ml.endpoint_email_ml_pipeline import EndpointEmailMLPipeline as _EEMPL
    _email_pipeline = _EEMPL()
except Exception:
    _email_pipeline = None

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
        # ML-based email detectors (URL risk, attachment, BEC)
        if _email_pipeline is not None:
            ev_dict = {
                'url': e.uri or '',
                'redirect_depth': e.raw.get('redirect_depth', 0) if e.raw else 0,
                'attachment_filename': e.file_name or '',
                'compressed_size': e.raw.get('compressed_size', 0) if e.raw else 0,
                'uncompressed_size': e.raw.get('uncompressed_size', 0) if e.raw else 0,
                'from_addr': e.raw.get('from_addr') or e.raw.get('sender') or e.user or '' if e.raw else (e.user or ''),
                'reply_to': e.raw.get('reply_to', '') if e.raw else '',
                'display_name': e.raw.get('display_name', '') if e.raw else '',
                'to_addr': e.raw.get('to_addr', '') if e.raw else '',
                'subject': e.subject or '',
            }
            try:
                ml_factors = _email_pipeline.analyze_email_event(ev_dict)
            except Exception:
                ml_factors = []
            for mf in ml_factors:
                out.append(FactorEmit(
                    name=mf.get('factor', 'unknown'),
                    nodes=[f"mailbox:{e.mailbox or e.user or 'unknown'}"],
                    domain='email',
                    confidence=mf.get('confidence', 0.5),
                    ts=e.timestamp,
                ))
        # url_shortener_risk (simplified: subject contains shortened URL keyword)
        if e.subject and 'bit.ly' in e.subject.lower():
            out.append(FactorEmit(name='url_shortener_risk', nodes=['domain:bit.ly'], domain='email', confidence=0.5, ts=e.timestamp))
        # mailbox_forward_rule_added (simplified tag)
        if 'forward_rule_added' in e.threat_tags:
            out.append(FactorEmit(name='mailbox_forward_rule_added', nodes=[f"mailbox:{e.mailbox or 'unknown'}"], domain='email', confidence=0.65, ts=e.timestamp))
    return out
