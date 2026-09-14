import time
from incidents.aggregator import IncidentAggregator

def test_incident_overlap_and_merge():
    agg = IncidentAggregator(window_seconds=300, factor_overlap=1)
    e1 = {'event_id':'a','src_host':'alpha','ts':time.time()}
    inc1 = agg.ingest(e1, ['f1'])
    e2 = {'event_id':'b','src_host':'alpha','ts':time.time()+1}
    inc2 = agg.ingest(e2, ['f2'])
    # Same host + factor overlap=1 (f2 new) merges into existing incident
    assert inc1['id'] == inc2['id']
    assert 'f2' in inc1['factors']

def test_incident_pruning():
    agg = IncidentAggregator(window_seconds=1, factor_overlap=1)
    now = time.time()
    agg.ingest({'event_id':'old','src_host':'beta','ts':now - 5}, ['x'])
    time.sleep(1.1)
    agg.ingest({'event_id':'new','src_host':'beta','ts':time.time()}, ['y'])
    incs = agg.list_incidents()
    # Old incident pruned; new one remains
    assert any('new' in [e['id'] for e in inc['events']] for inc in incs)