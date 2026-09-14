import os
import json
from src.incident.persistence import upsert_incident, incident_fingerprint, load_incident  # type: ignore

def test_incident_upsert(tmp_path):
    os.environ['INCIDENT_STORE_DIR'] = str(tmp_path)
    ev = {'dataset_id':'ds1','event_id':'e1','host':'host1','user':'u1','value':123}
    r1 = upsert_incident(ev)
    fp = incident_fingerprint(ev)
    assert r1['fingerprint'] == fp
    r2 = upsert_incident(ev)
    assert r2['count'] >= 2
    loaded = load_incident(fp)
    assert loaded is not None
