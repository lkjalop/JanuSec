from typing import List
from ..canonical_event import CanonicalEvent

class FactorEmit(dict):
    pass

def extract_api_factors(events: List[CanonicalEvent]) -> List[FactorEmit]:
    out: List[FactorEmit] = []
    by_user = {}
    for e in events:
        if e.source_type != 'api':
            continue
        by_user.setdefault(e.user or 'unknown', []).append(e)
    for user, lst in by_user.items():
        lst.sort(key=lambda x: x.timestamp)
        status_hist = [ev.status for ev in lst if ev.status]
        if status_hist.count('429') >= 2:
            out.append(FactorEmit(name='rate_limit_near_breach', nodes=[f"user:{user}"], domain='api', confidence=0.55, ts=lst[-1].timestamp))
        # mass_download_pattern simplified: many 200 with same endpoint prefix
        endpoints = {}
        for ev in lst:
            if ev.api_endpoint and ev.status == '200':
                pref = ev.api_endpoint.split('/',2)[1] if '/' in ev.api_endpoint else ev.api_endpoint
                endpoints[pref] = endpoints.get(pref,0)+1
        if any(c >= 5 for c in endpoints.values()):
            out.append(FactorEmit(name='mass_download_pattern', nodes=[f"user:{user}"], domain='api', confidence=0.6, ts=lst[-1].timestamp))
        # auth_token_reuse_across_ips heuristic: same user events with >2 distinct src_ip and shared token
        tokens = {}
        for ev in lst:
            tok = ev.raw.get('auth_token') if ev.raw else None
            if tok and ev.src_ip:
                tokens.setdefault(tok, set()).add(ev.src_ip)
        for tok, ips in tokens.items():
            if len(ips) >= 3:
                out.append(FactorEmit(name='auth_token_reuse_across_ips', nodes=[f"user:{user}"], domain='api', confidence=0.62, ts=lst[-1].timestamp))
    return out
