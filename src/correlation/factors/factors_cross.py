from typing import List
from ..canonical_event import CanonicalEvent

class FactorEmit(dict):
    pass

def extract_cross_domain_factors(events: List[CanonicalEvent]) -> List[FactorEmit]:
    out: List[FactorEmit] = []
    users = {e.user for e in events if e.user}
    data_events = any(e.source_type=='data' for e in events)
    iam_events = any(e.source_type=='iam' for e in events)
    api_events = any(e.source_type=='api' for e in events)
    if data_events and iam_events and api_events and users:
        out.append(FactorEmit(name='multi_stage_escalation_chain', nodes=[f"user:{next(iter(users))}"], domain='cross', confidence=0.6, ts=events[-1].timestamp if events else 0.0))
    # Data staging / exfil sequencing
    repos = [e.repository for e in events if e.source_type=='data' and e.repository]
    large_outbound = any(e.source_type=='data' and e.direction=='outbound' and (e.data_volume_bytes or 0) > 5_000_000 for e in events)
    if len(set(repos)) >= 2:
        out.append(FactorEmit(name='data_staging_phase', nodes=['aggregate:data'], domain='cross', confidence=0.55, ts=events[-1].timestamp if events else 0.0))
    if len(set(repos)) >= 2 and large_outbound:
        out.append(FactorEmit(name='data_staging_then_exfil', nodes=['aggregate:data'], domain='cross', confidence=0.6, ts=events[-1].timestamp if events else 0.0))
        out.append(FactorEmit(name='exfil_after_staging', nodes=['aggregate:data'], domain='cross', confidence=0.62, ts=events[-1].timestamp if events else 0.0))
    return out
