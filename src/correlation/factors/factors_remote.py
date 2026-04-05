from typing import List
from ..canonical_event import CanonicalEvent

class FactorEmit(dict):
    pass

def extract_remote_factors(events: List[CanonicalEvent]) -> List[FactorEmit]:
    out: List[FactorEmit] = []
    by_user = {}
    for e in events:
        if e.source_type != 'remote':
            continue
        by_user.setdefault(e.user or 'unknown', []).append(e)
    for user, lst in by_user.items():
        lst.sort(key=lambda x: x.timestamp)
        fail_count = 0
        success_after_fail = False
        geo_seq = []
        device_fp_seen = set()
        for ev in lst:
            if ev.outcome == 'fail' or (ev.status and ev.status.lower() == 'fail'):
                fail_count += 1
            if fail_count >= 3 and (ev.outcome == 'success' or (ev.status and ev.status.lower() == 'success')):
                success_after_fail = True
            if ev.geo_src:
                geo_seq.append((ev.geo_src, ev.timestamp))
            fp = ev.raw.get('device_fp') if ev.raw else None
            if fp and fp not in device_fp_seen:
                device_fp_seen.add(fp)
                out.append(FactorEmit(name='new_device_fingerprint', nodes=[f"user:{user}"], domain='remote', confidence=0.55, ts=ev.timestamp))
        if success_after_fail:
            out.append(FactorEmit(name='vpn_bruteforce_pattern', nodes=[f"user:{user}"], domain='remote', confidence=0.7, ts=lst[-1].timestamp))
        if len(geo_seq) >= 2:
            # simple impossible travel heuristic: two distinct geos within <600s
            first_geo, first_ts = geo_seq[0]
            last_geo, last_ts = geo_seq[-1]
            if first_geo != last_geo and (last_ts - first_ts) < 600:
                out.append(FactorEmit(name='impossible_travel_login', nodes=[f"user:{user}"], domain='remote', confidence=0.65, ts=last_ts))
        # rdp_high_frequency simplified: many dst_ip touches
        dst_ips = {ev.dst_ip for ev in lst if ev.dst_ip}
        if len(dst_ips) >= 4:
            out.append(FactorEmit(name='rdp_high_frequency', nodes=[f"user:{user}"], domain='remote', confidence=0.6, ts=lst[-1].timestamp))
    return out
