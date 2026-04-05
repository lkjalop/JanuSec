import sys
sys.path.insert(0, r'D:\AI\Threat_thy_sniffer')
import importlib
rt = importlib.import_module('src.api.runtime_state')

# clear cache
try:
    rt.DECISION_CACHE.clear()
except Exception:
    pass

class Dummy: pass

d1 = Dummy(); d1.event_id='evt-mitre-legacy-1'; d1.verdict='malicious'; d1.confidence=0.95; d1.factors=['mitre_TA0008']; d1.tenant_id='public'
d2 = Dummy(); d2.event_id='evt-mitre-direct-1'; d2.verdict='review'; d2.confidence=0.8; d2.factors=['T1566.001']; d2.tenant_id='public'

rt.DECISION_CACHE[d1.event_id] = d1
rt.DECISION_CACHE[d2.event_id] = d2

import re

def extract_mitre_from_factor(factor: str):
    out=[]
    if not isinstance(factor,str):
        return out
    s=factor.strip()
    low=s.lower()
    if low.startswith('mitre:') or low.startswith('mitre_') or low.startswith('mitre-'):
        if ':' in s:
            s = s.split(':',1)[1]
        elif '_' in s:
            s = s.split('_',1)[1]
        elif '-' in s:
            s = s.split('-',1)[1]
        s = s.strip()
    for m in re.findall(r'T\d{4}(?:\.\d{3})?', s, flags=re.IGNORECASE):
        out.append(m.upper())
    for m in re.findall(r'TA\d{4}', s, flags=re.IGNORECASE):
        out.append(m.upper())
    return out

counts = {}
for d in list(rt.DECISION_CACHE.values()):
    facs = getattr(d, 'factors', []) or []
    for f in facs:
        for t in extract_mitre_from_factor(f):
            counts[t] = counts.get(t,0)+1

print('counts:', counts)
