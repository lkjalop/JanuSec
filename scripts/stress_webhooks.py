"""Stress test script to POST synthetic XDR and CyberStash webhooks to local JanuSec server.

Usage:
    python scripts/stress_webhooks.py --base http://localhost:8080 --count 200 --interval 0.05

The script will:
 - poll /health until ready (timeout 30s)
 - register an XDR integrator ID with a secret
 - send alternating XDR and CyberStash webhooks signed as required
"""
from __future__ import annotations
import argparse
import hashlib
import hmac
import json
import random
import string
import time
from typing import Any

import requests


def sign_hmac(secret: str, body: bytes, ts: int) -> str:
    mac = hmac.new(secret.encode('utf-8'), msg=str(ts).encode('utf-8') + b'.' + body, digestmod=hashlib.sha256)
    return mac.hexdigest()


def sign_xdr(secret: str, body: bytes, ts: str) -> str:
    # XDR signing (integrator-specific) uses ts + '.' + body as in tests
    return hmac.new(secret.encode('utf-8'), msg=ts.encode('utf-8') + b'.' + body, digestmod=hashlib.sha256).hexdigest()


def random_ip() -> str:
    return f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"


def random_domain() -> str:
    s = ''.join(random.choices(string.ascii_lowercase, k=8))
    return s + random.choice(['.com', '.net', '.test', '.tk'])


def wait_for_health(base: str, timeout: int = 30) -> bool:
    url = base.rstrip('/') + '/health'
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=2)
            if r.status_code == 200:
                print('Server healthy')
                return True
        except Exception:
            pass
        time.sleep(0.5)
    print('Server did not become healthy in time')
    return False


def register_xdr(base: str, integrator_id: str, secret: str) -> bool:
    url = f"{base.rstrip('/')}/api/v1/integrations/xdr/register?integrator_id={integrator_id}&secret={secret}"
    try:
        r = requests.post(url, timeout=5)
        print('XDR register', r.status_code, r.text)
        return r.status_code == 200
    except Exception as e:
        print('XDR register failed', e)
        return False


def post_xdr(base: str, integrator_id: str, secret: str, payload: dict[str, Any]) -> None:
    url = f"{base.rstrip('/')}/api/v1/integrations/xdr/webhook"
    body = json.dumps({'events':[payload]}).encode('utf-8')
    ts = str(int(time.time()))
    sig = sign_xdr(secret, body, ts)
    headers = {
        'X-Integrator-ID': integrator_id,
        'X-Timestamp': ts,
        'X-Signature': sig,
        'Content-Type': 'application/json'
    }
    try:
        r = requests.post(url, data=body, headers=headers, timeout=5)
        print('xdr->', r.status_code, r.text[:200])
    except Exception as e:
        print('xdr post error', e)


def post_cyberstash(base: str, secret: str, payload: dict[str, Any]) -> None:
    url = f"{base.rstrip('/')}/api/v1/integrations/cyberstash/webhook"
    body = json.dumps(payload).encode('utf-8')
    ts = int(time.time())
    sig = sign_hmac(secret, body, ts)
    headers = {
        'X-Timestamp': str(ts),
        'X-Signature': sig,
        'Content-Type': 'application/json'
    }
    try:
        r = requests.post(url, data=body, headers=headers, timeout=5)
        print('cs->', r.status_code, r.text[:200])
    except Exception as e:
        print('cs post error', e)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--base', default='http://localhost:8080')
    p.add_argument('--count', type=int, default=200)
    p.add_argument('--interval', type=float, default=0.05)
    p.add_argument('--xdr-integrator', default='stress')
    p.add_argument('--xdr-secret', default='stresssecret')
    p.add_argument('--cyber-secret', default='cyber-secret')
    args = p.parse_args()

    if not wait_for_health(args.base, timeout=30):
        return

    # Register integrator for XDR
    ok = register_xdr(args.base, args.xdr_integrator, args.xdr_secret)
    if not ok:
        print('Warning: xdr register may have failed')

    for i in range(args.count):
        # craft a synthetic event
        ev = {
            'id': f'stress-{i}-{int(time.time()*1000)}',
            'type': random.choice(['net','process','dns','http']),
            'src_ip': random_ip(),
            'dst_ip': random_ip(),
            'domain': random_domain(),
            'ts': time.time()
        }
        # send both endpoints
        post_xdr(args.base, args.xdr_integrator, args.xdr_secret, ev)
        post_cyberstash(args.base, args.cyber_secret, {'id': ev['id'], 'alert': 'suspicious', 'meta': ev})
        time.sleep(args.interval)


if __name__ == '__main__':
    main()
