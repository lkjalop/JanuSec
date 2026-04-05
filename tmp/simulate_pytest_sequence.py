import os
os.environ['PLATFORM_LITE_INIT'] = '1'
import importlib
# Import app
appmod = importlib.import_module('src.api.app')
app = getattr(appmod, 'app')
# Import conftest and run session_setup to register fallback router
import tests.conftest as conf
sess = conf.session_setup()
# run setup portion until first yield
next(sess)
from fastapi.testclient import TestClient
client = TestClient(app)
# set env after client creation (mimic test order)
os.environ['MAX_CSV_ROWS'] = '100'
# Build CSV
lines=['a,b,c']+[f"{i},{i+1},{i+2}" for i in range(1000)]
data=('\n'.join(lines)).encode('utf-8')
r=client.post('/api/v1/upload/files', files={'files':('big.csv',data,'text/csv')}, headers={'x-api-key':'devkey123'})
print('status', r.status_code)
try:
    import json
    print(json.dumps(r.json(), indent=2)[:4000])
except Exception as e:
    print('json failed', e, r.text[:2000])
# cleanup: advance generator to let teardown run
try:
    next(sess)
except StopIteration:
    pass
