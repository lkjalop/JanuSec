from src.api import graph_session_endpoints as gse
from tests.test_graph_session import make_session_payload
s1 = make_session_payload(users=['alice'], hosts=['host1'], ips=['10.0.0.1'], hashes=['h1'], domains=['d1'])
s2 = make_session_payload(users=['bob','alice'], hosts=['host2'], ips=['10.0.0.2','10.0.0.1'], hashes=['h2'], domains=['d2'])
# Simulate sessions_input as endpoint does (persisted inline sessions)
sessions_input = [('s1', {'id':'s1','data': s1}), ('s2', {'id':'s2','data': s2})]
resp = gse.build_session_response(sessions_input)
print('correlation:', resp['correlation'])
print('correlation type:', type(resp['correlation'][0][1]))
