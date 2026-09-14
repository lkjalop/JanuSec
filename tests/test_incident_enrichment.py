import time
from incidents.aggregator import IncidentAggregator

def test_incident_enrichment_mapping():
    agg = IncidentAggregator(window_seconds=60)
    evt = {'event_id':'e1','src_host':'HOST1','ts':time.time()}
    inc = agg.ingest(evt, ['baseline:known_bad_ip','net:beacon_periodic'])
    # Enrichment should appear either directly in stored incident or after list call
    enr = inc.get('framework_enrichment')
    if not enr:
        # fallback through list view
        enr = next(i for i in agg.list_incidents() if i['id']==inc['id']).get('framework_enrichment')
    assert enr
    assert 'baseline:known_bad_ip' in enr
    assert enr['baseline:known_bad_ip']['mitre']
