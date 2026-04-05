import os
from src.api.app import app
from fastapi.testclient import TestClient
client = TestClient(app)
# Set MAX_CSV_ROWS after TestClient creation
os.environ['MAX_CSV_ROWS'] = '100'
lines=['a,b,c']+[f"{i},{i+1},{i+2}" for i in range(1000)]
data=('\n'.join(lines)).encode('utf-8')
r=client.post('/api/v1/upload/files', files={'files':('big.csv',data,'text/csv')}, headers={'x-api-key':'devkey123'})
print('status', r.status_code)
import json
print(json.dumps(r.json(), indent=2)[:4000])
