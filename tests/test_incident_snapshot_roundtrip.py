import os, asyncio, time, json
from incidents.aggregator import IncidentAggregator
import pytest

@pytest.mark.asyncio
async def test_incident_snapshot_roundtrip(tmp_path):
    snap = tmp_path / 'incidents_snapshot.json'
    agg = IncidentAggregator(window_seconds=300)
    agg.snapshot_path = str(snap)
    # Ingest two events into a single incident
    ev1 = {'event_id':'e1','src_host':'h1','ts': time.time()}
    ev2 = {'event_id':'e2','src_host':'h1','ts': time.time()+1}
    inc1 = agg.ingest(ev1, ['net:beacon_periodic'])
    inc2 = agg.ingest(ev2, ['net:beacon_periodic','net:beacon_periodic'])
    assert inc1['id'] == inc2['id']
    agg.save_snapshot()
    assert snap.exists()
    # Load into a new aggregator
    agg2 = IncidentAggregator(window_seconds=300)
    agg2.snapshot_path = str(snap)
    agg2.load_snapshot()
    incs = agg2.list_incidents()
    assert len(incs) == 1
    restored = incs[0]
    # Ensure factors union persisted
    assert 'net:beacon_periodic' in restored['factors']
    assert 'net:beacon_periodic' in restored['factors']
    # Ensure both events present
    assert len(restored['events']) == 2
