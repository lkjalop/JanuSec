from fastapi.testclient import TestClient
from src.api.app import create_app
app=create_app()
client=TestClient(app)
rows=[{'user':'a','host':'h','process':'p','sha256':'a'}]
payload={'session_id':'testsess','rows':rows,'org':'unittest','auto_llm':False}
r=client.post('/api/v1/assessments/deep_analyze', json=payload)
print('status', r.status_code)
print('text:', r.text)
try:
    print('json:', r.json())
except Exception as e:
    print('json error', e)
