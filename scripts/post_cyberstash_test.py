import hmac
import hashlib
import time
import requests
import json

secret = 's3cr3t-cs'
url = 'http://127.0.0.1:8080/api/v1/integrations/cyberstash/webhook'
payload = {'id': 'test-1', 'name': 'testfile.exe', 'malicious': False}
body = json.dumps(payload).encode('utf-8')
ts = int(time.time())
mac = hmac.new(secret.encode('utf-8'), msg=str(ts).encode('utf-8') + b'.' + body, digestmod=hashlib.sha256).hexdigest()
headers = {'X-Timestamp': str(ts), 'X-Signature': mac, 'Content-Type': 'application/json'}
print('POST', url)
print('Headers:', headers)
try:
    r = requests.post(url, data=body, headers=headers, timeout=10)
    print('status', r.status_code)
    print(r.text)
except Exception as e:
    print('Error posting:', e)
