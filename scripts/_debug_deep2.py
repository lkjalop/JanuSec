import sys, os
sys.path.insert(0, os.getcwd())
from fastapi.testclient import TestClient
from src.api.app import app
client=TestClient(app)
rows=[{'user':'a','host':'h','process':'p','sha256':'a'}]
payload={'session_id':'testsess','rows':rows,'org':'unittest','auto_llm':False}
r=client.post('/api/v1/assessments/deep_analyze', json=payload)
print('status', r.status_code)
print('headers', r.headers)
print('text:', repr(r.text))
try:
    print('json:', r.json())
except Exception as e:
    print('json parse error', e)
    import traceback
    traceback.print_exc()
