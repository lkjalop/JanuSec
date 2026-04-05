from fastapi.testclient import TestClient
from src.api.app import app
client = TestClient(app)
API_KEY = 'devkey123'
HEADERS = {'x-api-key': API_KEY}
from tests.test_graph_session import make_session_payload
s1 = make_session_payload(users=['alice'], hosts=['host1'], ips=['10.0.0.1'], hashes=['h1'], domains=['d1'])
s2 = make_session_payload(users=['bob','alice'], hosts=['host2'], ips=['10.0.0.2','10.0.0.1'], hashes=['h2'], domains=['d2'])
resp = client.post('/api/v1/graph/session/build', headers=HEADERS, json={'sessions':[{'id':'s1','data':s1},{'id':'s2','data':s2}]})
print('status', resp.status_code)
print('json', resp.json())
