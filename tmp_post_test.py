import os
from fastapi.testclient import TestClient
from src.api.app import app
client = TestClient(app)
API_KEY = os.getenv('TEST_API_KEY','devkey123')
HEADERS = {'x-api-key': API_KEY}
payload = {'registry_events': [{'key_path':'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell','value_name':'Shell','old_value':'explorer.exe','new_value':'badexplorer.exe'}]}
r = client.post('/api/v1/endpoint/malware/analyze', headers=HEADERS, json=payload)
print('status', r.status_code)
try:
    print('json:', r.json())
except Exception:
    print('text:', r.text)
