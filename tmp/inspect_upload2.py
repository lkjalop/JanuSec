import os, json
os.environ['PLATFORM_LITE_INIT']='1'
from fastapi.testclient import TestClient
from src.api.app import app
# create client first
client = TestClient(app)
# set MAX_CSV_ROWS after client creation (like test)
os.environ['MAX_CSV_ROWS'] = '100'
lines=['a,b,c']+[f'{i},{i+1},{i+2}' for i in range(1000)]
data=('\n'.join(lines)).encode('utf-8')
files={'files':('big.csv',data,'text/csv')}
r=client.post('/api/v1/upload/files', files=files, headers={'x-api-key':'devkey123'})
print('status', r.status_code)
print(json.dumps(r.json(), indent=2)[:2000])
