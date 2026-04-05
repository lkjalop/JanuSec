import time
from fastapi.testclient import TestClient
from src.api.app import app
from src.core.graph.hopgraph_lite import get_graph
import importlib, sys

client = TestClient(app)

g = get_graph()
g.edges_ts.clear()
g.observe({'edge_type': 'auth', 'user': 'dave', 'host': 'ha'})
g.observe({'edge_type': 'net', 'host': 'ha', 'peer': 'hb'})
seed = {'user':'dave','host':'ha'}

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

print('Before POST, server_mod._INCIDENT_STORE len=', len(server_mod._INCIDENT_STORE))
r = client.post('/api/v1/graph/reconstruct?attach_incident=true', json=seed, headers={'x-api-key':'devkey123'})
print('POST status', r.status_code)
import time as _t; _t.sleep(0.1)
print('persisted len', len(persisted))
if persisted:
    print('persisted[0] metadata keys', list(persisted[0].get('metadata',{}).keys()))

# Append into server_mod._INCIDENT_STORE as test does
rec = persisted[0]
server_mod._INCIDENT_STORE.append({'id': rec.get('event_id') or rec.get('id') or f"inc-{int(time.time()*1000)}", 'metadata': rec.get('metadata') or {}, 'tenant_id': rec.get('tenant_id'), 'ts': time.time()})
server_mod.decisions_repo = None
server_mod.DECISIONS_REPO = None
print('After append, server_mod._INCIDENT_STORE len=', len(server_mod._INCIDENT_STORE))

# Inspect sys.modules for modules with _INCIDENT_STORE
mods = []
for name, mod in list(sys.modules.items()):
    try:
        if not mod:
            continue
        other = getattr(mod, '_INCIDENT_STORE', None)
        if isinstance(other, list):
            mods.append((name, id(mod), len(other)))
    except Exception:
        continue
print('Modules with _INCIDENT_STORE:')
for m in mods:
    print(m)

# Now call the incidents endpoint
r2 = client.get('/api/v1/incidents', headers={'x-api-key':'devkey123'})
print('INCIDENTS status', r2.status_code)
print('INCIDENTS json:', r2.json())
