#!/usr/bin/env python3
import time,hashlib,hmac
from pathlib import Path
from fastapi.testclient import TestClient
from src.api.app import app

def mk(sig_secret, body, ts):
    return hmac.new(sig_secret.encode(), msg=str(ts).encode()+b'.'+body, digestmod=hashlib.sha256).hexdigest()

def main():
    client = TestClient(app)
    secret = 's3cr3t-cs'
    p = Path('dump/cybstash1_data.json')
    if not p.exists():
        print('missing payload')
        return
    b = p.read_bytes()
    ts = int(time.time())
    sig = mk(secret, b, ts)
    r1 = client.post('/api/v1/integrations/cyberstash/webhook', data=b, headers={'X-Timestamp':str(ts),'X-Signature':sig,'Content-Type':'application/json'})
    print('first', r1.status_code)
    try:
        print(r1.json())
    except Exception:
        print('not json')

    r2 = client.post('/api/v1/integrations/cyberstash/webhook', data=b, headers={'X-Timestamp':str(ts),'X-Signature':sig,'Content-Type':'application/json'})
    print('replay', r2.status_code, r2.text[:200])

    # bad sig
    bad = '00dead'
    r3 = client.post('/api/v1/integrations/cyberstash/webhook', data=b, headers={'X-Timestamp':str(int(time.time())),'X-Signature':bad,'Content-Type':'application/json'})
    print('bad sig', r3.status_code)

    # stale ts
    old_ts = int(time.time()) - 999999
    s_old = mk(secret, b, old_ts)
    r4 = client.post('/api/v1/integrations/cyberstash/webhook', data=b, headers={'X-Timestamp':str(old_ts),'X-Signature':s_old,'Content-Type':'application/json'})
    print('stale ts', r4.status_code)

if __name__ == '__main__':
    main()
