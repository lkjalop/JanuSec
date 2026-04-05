import os, json, time
from src.core.event_store import append_event, get_event_by_id, load_events, cleanup_expired
from src.api.ingest_controller_endpoints import state_get_event
from src.api.app import create_app
from fastapi.testclient import TestClient


def test_event_store_append_and_get(tmp_path, monkeypatch):
    p = tmp_path / 'events.jsonl'
    monkeypatch.setenv('EVENT_STORE_PATH', str(p))
    ev = {'event_id': 'evt_test1', 'sensor': 'generic', 'ts': time.time(), 'raw': {'k': 'v'}}
    assert append_event(ev)
    found = get_event_by_id('evt_test1')
    assert found and found.get('event_id') == 'evt_test1'


def test_timeline_resolver_api(tmp_path, monkeypatch):
    p = tmp_path / 'events.jsonl'
    monkeypatch.setenv('EVENT_STORE_PATH', str(p))
    app = create_app({'mode': 'test'})
    client = TestClient(app)
    # append two events
    e1 = {'event_id': 'evt_t1', 'sensor': 'generic', 'ts': time.time() - 5}
    e2 = {'event_id': 'evt_t2', 'sensor': 'generic', 'ts': time.time()}
    from src.core.event_store import append_event
    append_event(e1)
    append_event(e2)
    r = client.post('/api/v1/ingest/events/timeline', json={'events': ['evt_t1','evt_t2']})
    assert r.status_code == 200
    j = r.json()
    assert j['detail']['timeline'][0]['event_id'] == 'evt_t1'
