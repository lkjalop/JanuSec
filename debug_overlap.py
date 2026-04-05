from fastapi.testclient import TestClient
from src.api.app import app
from inspect import getsource, getfile
client=TestClient(app)
payload={'session_ids':['batch-overlap-A','batch-overlap-B'],'correlate':True,'ewma':False,'mapping':{'user':'user','host':'host','ip':'ip','file_hash':'file_hash','domain':'domain'}}
r=client.post('/api/v1/graph/session/build',json=payload)
print('status',r.status_code)
print('summary keys', list(r.json()['summary'].keys()))
print('overlap_details raw:', r.json()['summary'].get('overlap_details'))
try:
	from src.api.graph_sessions import build_session
	print('build_session file:', build_session.__code__.co_filename)
except Exception as e:
	print('Failed to introspect build_session:', e)
