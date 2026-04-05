from fastapi.testclient import TestClient
import src.api.app as appmod
client = TestClient(appmod.app)
resp = client.post('/api/v1/email/ingest', json={'sender':'a','recipient':'b','subject':'s'})
print('status email', resp.status_code, resp.text)
resp2 = client.post('/api/v1/remote_access/ingest', json={'src_ip':'1.1.1.1','user':'u','dest_host':'h'})
print('status remote', resp2.status_code, resp2.text)
resp3 = client.post('/api/v1/endpoints/log_batch', json={'events':[{'host':'h'}]})
print('status endpoint', resp3.status_code, resp3.text)
