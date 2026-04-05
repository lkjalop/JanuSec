import os, sqlite3
from fastapi.testclient import TestClient
os.environ['SESSION_BACKEND']='sqlite'
os.environ['SESSION_PERSIST_SQLITE_PATH']=r'C:/Users/Kevin J/AppData/Local/Temp/test_manual_sessions.db'
from src.api.app import app
client=TestClient(app)
r=client.post('/api/v1/graph/session/build', json={'session_ids':['X','Y'], 'correlate':True})
print('status', r.status_code)
print('json keys', list(r.json().keys()))
path=os.environ['SESSION_PERSIST_SQLITE_PATH']
print('db path', path, 'exists?', os.path.exists(path))
conn=sqlite3.connect(path)
cur=conn.cursor()
cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
print('tables', cur.fetchall())
try:
    cur.execute('SELECT id,json FROM sessions')
    print('sessions rows', cur.fetchall())
except Exception as e:
    print('query error', e)
conn.close()
