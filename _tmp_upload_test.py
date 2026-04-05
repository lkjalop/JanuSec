import urllib.request, json
from pathlib import Path
import sys
sys.path.insert(0,'c:/AI/janusec')

boundary = 'JanuSecBoundary1234567890'
filepath = Path('c:/AI/janusec/dump/Cyberstash_csv2.xlsx')
with open(filepath, 'rb') as f:
    file_bytes = f.read()
body = (
    f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filepath.name}"\r\nContent-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\r\n\r\n'
).encode() + file_bytes + f'\r\n--{boundary}--\r\n'.encode()

req = urllib.request.Request(
    'http://localhost:8090/api/v1/csv/upload',
    data=body, method='POST',
    headers={'x-api-key':'devkey123','X-Tenant-ID':'default','Content-Type':f'multipart/form-data; boundary={boundary}'}
)
try:
    with urllib.request.urlopen(req, timeout=90) as r:
        result = json.loads(r.read())
except urllib.error.HTTPError as e:
    print('HTTP', e.code, e.read().decode()[:500])
    raise SystemExit(1)

print('Keys:', list(result.keys()))
print('session:', result.get('session'))
print('graph_session:', result.get('graph_session'))
print('total_rows:', result.get('total_rows'))
print('processed:', result.get('processed'))
res = result.get('results') or []
print('results count:', len(res))
if res:
    print('First result keys:', list(res[0].keys()) if isinstance(res[0], dict) else type(res[0]))
    print('First result:', json.dumps(res[0], default=str)[:600])
