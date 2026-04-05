from fastapi.testclient import TestClient
from src.api.app import app

client = TestClient(app)
sample = "chrome.exe-1A2B3C4D.pf - LastRun: 2024-01-01 12:00:00 - Count: 5\nRun: MyApp = C:\\Tools\\myapp.exe /quiet"
files = {'file': ('sample.kape', sample)}
resp = client.post('/api/v1/kape/upload?async_process=false&trigger_sandbox=true', files=files, headers={'x-api-key':'devkey123'})
print('status', resp.status_code)
print('headers', dict(resp.headers))
try:
    j = resp.json()
    print('json ok:', j)
except Exception as e:
    print('json parse error', repr(e))
    print('text:', resp.text)
    print('content repr:', repr(resp.content[:2000]))
print('text:', resp.text)
print('content repr:', repr(resp.content[:500]))
