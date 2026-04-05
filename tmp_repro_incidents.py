import time
import importlib
import os
from fastapi.testclient import TestClient

os.environ['TEST_HELPERS_ENABLED'] = '1'
os.environ['INCIDENTS_DEBUG'] = '1'

from src.api.server import app
from src.core.graph.hopgraph_lite import get_graph

client = TestClient(app)

def run():
    g = get_graph()
    g.edges_ts.clear()
    g.observe({'edge_type': 'auth', 'user': 'dave', 'host': 'ha'})
    g.observe({'edge_type': 'net', 'host': 'ha', 'peer': 'hb'})
    seed = {'user': 'dave', 'host': 'ha'}

    persisted = []

    class FakeRepo:
        def __init__(self):
            self._mem = []
        async def persist(self, rec):
            self._mem.append(rec)
            persisted.append(rec)
        async def list_recent_decisions(self, limit=50, tenant_id=None):
            return list(self._mem[-limit:])
        def list_memory(self):
            return list(self._mem)

    fake = FakeRepo()
    import src.api.server as server_mod
    server_mod.decisions_repo = fake

    class FakeIncidentsRepo:
        async def upsert_incident(self, incident_id, payload, tenant_id=None):
            await fake.persist({'event_id': incident_id, **payload})
    server_mod.incidents_repo = FakeIncidentsRepo()

    # call reconstruct
    r = client.post('/api/v1/graph/reconstruct?attach_incident=true', json=seed, headers={'x-api-key': 'devkey123'})
    print('POST status', r.status_code, r.text)
    time.sleep(0.1)
    print('persisted len', len(persisted))
    if persisted:
        print('persisted[0] metadata keys', list(persisted[0].get('metadata', {}).keys()))

    # append to in-memory incident store
    server_mod._INCIDENT_STORE.append({
        'id': persisted[0].get('event_id') if persisted else f"inc-{int(time.time()*1000)}",
        'metadata': persisted[0].get('metadata') if persisted else {},
        'tenant_id': persisted[0].get('tenant_id') if persisted else None,
        'ts': time.time(),
    })
    server_mod.decisions_repo = None
    server_mod.DECISIONS_REPO = None

    r2 = client.get('/api/v1/incidents', headers={'x-api-key': 'devkey123'})
    print('GET /api/v1/incidents status', r2.status_code)
    print('GET body:', r2.json())

if __name__ == '__main__':
    run()
