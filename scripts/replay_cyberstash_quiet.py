#!/usr/bin/env python3
import time,hashlib,hmac,logging
from pathlib import Path
from fastapi.testclient import TestClient
from src.api.app import app

# Reduce noisy startup logs when using TestClient in automation
for _n in ('src.api.app','src.api.startup','uvicorn','asyncio','httpx'):
    logging.getLogger(_n).setLevel(logging.ERROR)

def make_sig(secret, body, ts):
    return hmac.new(secret.encode(), msg=str(ts).encode()+b'.'+body, digestmod=hashlib.sha256).hexdigest()

def main():
    client = TestClient(app)
    secret = 's3cr3t-cs'
    for p in ['dump/cybstash1_data.json','dump/cybstash2_data.json']:
        pb = Path(p)
        if not pb.exists():
            print('Missing', p)
            continue
        body = pb.read_bytes()
        ts = int(time.time())
        sig = make_sig(secret, body, ts)
        r = client.post('/api/v1/integrations/cyberstash/webhook', data=body, headers={'X-Timestamp': str(ts), 'X-Signature': sig, 'Content-Type': 'application/json'})
        print(p, r.status_code, flush=True)
        try:
            print(r.json(), flush=True)
        except Exception:
            print('Non-JSON response:', r.text[:400], flush=True)

if __name__ == '__main__':
    main()
