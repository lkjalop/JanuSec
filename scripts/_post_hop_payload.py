import requests, sys
p='tmp/hop_payload3.json'
print('posting', p)
with open(p,'rb') as fh:
    r = requests.post('http://127.0.0.1:8080/api/v1/graph/session/build', headers={'Content-Type':'application/json'}, data=fh)
print('status', r.status_code)
print(r.text)
if r.status_code >= 400:
    sys.exit(2)
