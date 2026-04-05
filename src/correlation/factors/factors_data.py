from typing import List
from ..canonical_event import CanonicalEvent

class FactorEmit(dict):
    pass

def extract_data_factors(events: List[CanonicalEvent]) -> List[FactorEmit]:
    out: List[FactorEmit] = []
    by_user = {}
    for e in events:
        if e.source_type != 'data':
            continue
        by_user.setdefault(e.user or 'unknown', []).append(e)
    for user, lst in by_user.items():
        total = sum(ev.data_volume_bytes or 0 for ev in lst)
        if total > 10_000_000:  # 10MB threshold example
            out.append(FactorEmit(name='outbound_volume_spike', nodes=[f"user:{user}"], domain='data', confidence=0.65, ts=lst[-1].timestamp))
        if any(ev.direction == 'outbound' and (ev.data_volume_bytes or 0) > 5_000_000 for ev in lst):
            out.append(FactorEmit(name='large_email_attachment_exfil', nodes=[f"user:{user}"], domain='data', confidence=0.6, ts=lst[-1].timestamp))
        # staging_directory_population simplified: repository appears multiple times
        repos = {ev.repository for ev in lst if ev.repository}
        if len(repos) >= 3:
            out.append(FactorEmit(name='staging_directory_population', nodes=[f"user:{user}"], domain='data', confidence=0.55, ts=lst[-1].timestamp))
        # compression_before_transfer heuristic: presence of compressed indicator then large outbound
        compressed_flag = any(str(ev.raw).lower().find('.zip')!=-1 or str(ev.raw).lower().find('.gz')!=-1 for ev in lst)
        if compressed_flag and any((ev.data_volume_bytes or 0) > 5_000_000 for ev in lst):
            out.append(FactorEmit(name='compression_before_transfer', nodes=[f"user:{user}"], domain='data', confidence=0.58, ts=lst[-1].timestamp))
    return out
