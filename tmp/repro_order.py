import os, json
from fastapi.testclient import TestClient
os.environ['PLATFORM_LITE_INIT']='1'
from src.api.app import app
client=TestClient(app)
# Simulate pytest: set MAX_CSV_ROWS via monkeypatch (after client created)
os.environ['MAX_CSV_ROWS']='100'
lines=['a,b,c']+[f"{i},{i+1},{i+2}" for i in range(1000)]
data=('\n'.join(lines)).encode('utf-8')
res=client.post('/api/v1/upload/files', files={'files':('big.csv',data,'text/csv')}, headers={'x-api-key':'devkey123'})
print('status', res.status_code)
j=res.json()
print('handler top-level:', j.get('handler'))
print('first result analysis truncated:', j['results'][0].get('analysis',{}).get('truncated'))
print(json.dumps(j['results'][0]['analysis'], indent=2)[:800])
