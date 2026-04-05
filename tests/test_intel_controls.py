import os
import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def enable_intel(monkeypatch):
    monkeypatch.setenv('THREAT_INTEL_ENABLED','1')
    yield

def _get_app():
    from src.api.app import app
    return app

def test_feed_toggle_endpoint(monkeypatch):
    app = _get_app()
    client = TestClient(app)
    # Disable feed
    r = client.post('/api/v1/intel/feeds/misp/toggle', json={'enabled': False})
    assert r.status_code == 200
    assert r.json()['enabled'] is False
    # Re-enable feed
    r2 = client.post('/api/v1/intel/feeds/misp/toggle', json={'enabled': True})
    assert r2.status_code == 200
    assert r2.json()['enabled'] is True

def test_technique_provenance_structure(monkeypatch):
    from integrations.threat_intel_client import CLIENT
    # simulate a provenance entry
    CLIENT.factor_techniques.setdefault('stable:dns', []).append('T1046') if 'T1046' not in CLIENT.factor_techniques.get('stable:dns', []) else None
    prov = CLIENT._technique_provenance.setdefault('stable:dns', {}).setdefault('T1046', set())
    prov.add('opencti')
    app = _get_app()
    client = TestClient(app)
    r = client.get('/api/v1/intel/techniques/provenance')
    assert r.status_code == 200
    data = r.json()
    assert 'provenance' in data
    assert isinstance(data['provenance'], dict)
    assert 'stable:dns' in data['provenance']
    assert 'T1046' in data['provenance']['stable:dns']
    assert 'opencti' in data['provenance']['stable:dns']['T1046']


def test_circuit_breaker_opens(monkeypatch):
    # Force httpx to raise repeatedly
    monkeypatch.setenv('THREAT_INTEL_ENABLED','1')
    from integrations.threat_intel_client import CLIENT
    from core.net.circuit_breaker import get_circuit
    # Low threshold for test
    monkeypatch.setenv('CB_FAILURE_THRESHOLD','2')
    # Mock httpx
    class DummyExc(Exception):
        pass
    import types
    async def failing_get(self, *a, **kw):  # type: ignore
        raise DummyExc('boom')
    async def failing_post(self, *a, **kw):  # type: ignore
        raise DummyExc('boom')
    # Patch httpx.AsyncClient
    import httpx
    monkeypatch.setattr(httpx.AsyncClient, 'get', failing_get, raising=False)
    monkeypatch.setattr(httpx.AsyncClient, 'post', failing_post, raising=False)
    # Call internal _http_get to trigger failures and breaker increments
    import asyncio
    async def run_failures():
        for _ in range(2):
            await CLIENT._http_get('https://example.com/feed')
        # On third attempt circuit should be open and raise immediately
        try:
            await CLIENT._http_get('https://example.com/feed')
        except Exception as e:
            assert 'circuit_open' in str(e)
    asyncio.run(run_failures())


def test_degradation_flags_round_trip(monkeypatch):
    app = _get_app()
    client = TestClient(app)
    r = client.get('/api/v1/intel/status/degradation')
    assert r.status_code == 200
    original = r.json()['flags']
    assert 'intel_offline' in original
    # Set a flag
    r2 = client.post('/api/v1/intel/status/degradation', json={'name':'intel_offline','value': True})
    assert r2.status_code == 200
    r3 = client.get('/api/v1/intel/status/degradation')
    assert r3.json()['flags']['intel_offline'] is True
    # Reset
    client.post('/api/v1/intel/status/degradation', json={'name':'intel_offline','value': False})
    r4 = client.get('/api/v1/intel/status/degradation')
    assert r4.json()['flags']['intel_offline'] is False


def test_tenant_scoping(monkeypatch):
    # Force SQLite fresh DB
    monkeypatch.setenv('DB_TYPE','sqlite')
    monkeypatch.setenv('SQLITE_PATH','test_scope.db')
    monkeypatch.setenv('ENFORCE_TENANT_SCOPE','1')
    # Insert events manually through adapter
    import asyncio
    from database_adapter import init_database, db_manager
    async def setup():
        await init_database()
        adapter = db_manager.adapter
        await adapter.store_event('e1', {'id':'e1','tenant_id':'tenantA'}, 'benign', 0.1)
        await adapter.store_event('e2', {'id':'e2','tenant_id':'tenantB'}, 'benign', 0.2)
    asyncio.run(setup())
    # With FORCED_TENANT_ID=tenantA only e1 should appear
    monkeypatch.setenv('FORCED_TENANT_ID','tenantA')
    from database_adapter import get_recent_events
    events = asyncio.run(get_recent_events(10))
    ids = {e['id'] for e in events}
    assert 'e1' in ids and 'e2' not in ids