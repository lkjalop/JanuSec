import os,json
os.environ['FAST_TEST_MODE']='1'
os.environ['API_KEYS_JSON']=json.dumps([{'key':'testkey','scopes':['feedback.write','factors.search','risk.read']}])
from fastapi.testclient import TestClient
from src.api.server import app
client=TestClient(app)
resp=client.get('/api/v1/risk/calibration/export?a=1&k=1', headers={'x-api-key':'testkey'})
print(resp.status_code)
try:
    print(resp.json())
except Exception:
    print(resp.text)
