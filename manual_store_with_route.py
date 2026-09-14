import os, sqlite3, json, tempfile
from fastapi.testclient import TestClient
from src.api.app import app

with tempfile.TemporaryDirectory() as td:
    db_path = td + '/sessions.db'
    os.environ['SESSION_BACKEND']='sqlite'
    os.environ['SESSION_PERSIST_SQLITE_PATH']=db_path
    client = TestClient(app)
    r = client.post('/api/v1/graph/session/build', json={'session_ids':['A','B'], 'correlate':True})
    print('status', r.status_code)
    print('resp', r.json())
    print('expected db path', db_path, 'exists?', os.path.exists(db_path))
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    print('tables', cur.fetchall())
    conn.close()
