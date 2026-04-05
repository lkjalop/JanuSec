import os, sqlite3, time, tempfile
from fastapi.testclient import TestClient
from src.api.app import app

td = tempfile.mkdtemp()
path = td + '/sessions.db'
os.environ['SESSION_BACKEND']='sqlite'
os.environ['SESSION_PERSIST_SQLITE_PATH']=path
os.environ['SESSION_TTL_SECONDS']='1'
client = TestClient(app)
r = client.post('/api/v1/graph/session/build', json={'session_ids':['X'], 'correlate':False})
print('build status', r.status_code)
sid = r.json()['session_id']
print('sid', sid)
conn = sqlite3.connect(path)
cur = conn.cursor()
cur.execute('SELECT id, updated_at FROM sessions')
print('before update rows', cur.fetchall())
old = time.time() - 3600
cur.execute('UPDATE sessions SET updated_at=? WHERE id=?', (old, sid))
conn.commit()
cur.execute('SELECT id, updated_at FROM sessions')
print('after update rows', cur.fetchall())
conn.close()
# Clear in-memory store
from src.api.graph_sessions import _SESSIONS
_SESSIONS.pop(sid, None)
# Direct store.load TTL check
from src.api.session_store import reset_session_store, get_session_store
reset_session_store()
store = get_session_store()
print('store backend', type(store).__name__)
print('store.load result', store.load(sid))
# Call get session endpoint
resp = client.get(f'/api/v1/graph/session/{sid}')
print('get status', resp.status_code)
print('get body', resp.json() if resp.status_code==200 else resp.text)
