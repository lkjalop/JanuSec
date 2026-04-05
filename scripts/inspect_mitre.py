import sys
import os
# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.api import runtime_state
from src.api import report_aggregation as ra
class Dummy: pass

d1 = Dummy()
d1.event_id='evt-mitre-legacy-1'; d1.verdict='malicious'; d1.confidence=0.95; d1.factors=['mitre_TA0008']; d1.tenant_id='public'
d2 = Dummy()
d2.event_id='evt-mitre-direct-1'; d2.verdict='review'; d2.confidence=0.8; d2.factors=['T1566.001']; d2.tenant_id='public'

runtime_state.cache_set(d1.event_id, d1)
runtime_state.cache_set(d2.event_id, d2)

res = ra.aggregate_decisions()
print('TOP MITRE (raw):', res.get('top_mitre'))
print('Top keys:', {t['technique'] for t in res.get('top_mitre',[])})
print('Flagged:', res.get('flagged_events'))
print('Autoblocked:', res.get('autoblocked_samples'))
