#!/usr/bin/env python3
"""Replay CyberStash webhook payloads from dump/ using TestClient and HMAC signing.
Useful for local validation without needing an external server.
"""
import hashlib
import hmac
import json
import time
from pathlib import Path

from fastapi.testclient import TestClient

from src.api.app import app


def make_sig(secret: str, body: bytes, ts: int) -> str:
    mac = hmac.new(secret.encode('utf-8'), msg=str(ts).encode('utf-8') + b'.' + body, digestmod=hashlib.sha256)
    return mac.hexdigest()


def post_file(client: TestClient, path: Path, secret: str):
    if not path.exists():
        print('Missing file', path)
        return
    body = path.read_bytes()
    ts = int(time.time())
    sig = make_sig(secret, body, ts)
    headers = {'X-Timestamp': str(ts), 'X-Signature': sig, 'Content-Type': 'application/json'}
    r = client.post('/api/v1/integrations/cyberstash/webhook', data=body, headers=headers)
    print(f'POST {path.name} -> {r.status_code}')
    try:
        print(r.json())
    except Exception:
        print('Non-json response:', r.text[:400])


def main():
    secret = 's3cr3t-cs'
    client = TestClient(app)
    p1 = Path('dump/cybstash1_data.json')
    p2 = Path('dump/cybstash2_data.json')
    print('Posting', p1)
    post_file(client, p1, secret)
    print('Posting', p2)
    post_file(client, p2, secret)


if __name__ == '__main__':
    main()
