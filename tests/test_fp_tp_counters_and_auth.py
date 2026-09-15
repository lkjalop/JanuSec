import json
import os
from fastapi.testclient import TestClient
import src.api.server as server_mod
from src.core.correlation.rules import registry

client = TestClient(server_mod.app)


def test_fp_tp_counters_increment():
    # ensure counters start empty
    registry.record_false_positive('powershell_encoded_command')
    registry.record_true_positive('powershell_encoded_command')
    m = registry.get_metrics()
    assert m.get('powershell_encoded_command', {}).get('fp', 0) >= 1
    assert m.get('powershell_encoded_command', {}).get('tp', 0) >= 1


def test_graph_reconstruct_authenticated(monkeypatch):
    # stub incidents_repo.upsert_incident to avoid DB dependency
    class FakeInc:
        called = False
        async def upsert_incident(self, incident_id, payload, tenant_id=None):
            FakeInc.called = True
            return True

    monkeypatch.setitem(server_mod.__dict__, 'incidents_repo', FakeInc())

    # use the dev key which is default in many tests
    r = client.post('/api/v1/graph/reconstruct?attach_incident=true', json={'user':'z'}, headers={'x-api-key':'devkey123'})
    assert r.status_code == 200
