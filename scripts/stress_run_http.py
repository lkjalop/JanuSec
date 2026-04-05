"""End-to-end HTTP stress runner: register XDR integrator, post batches signed with HMAC to /api/v1/integrations/xdr/webhook via TestClient, and drain runtime_state.EVENT_QUEUE into GLOBAL_HOPGRAPH.

Usage: python scripts/stress_run_http.py --batches 200 --batch-size 100
"""
import os
import sys
import time
import json
import hmac
import hashlib
from random import randint

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fastapi.testclient import TestClient
from src.api.app import app
from src.api.runtime_state import EVENT_QUEUE
from src.graph.hopgraph import GLOBAL_HOPGRAPH


def make_event(i):
    return {'id': f'evt-{i}', 'src_host': f'host-{i%1000}', 'dst_ip': f'10.0.{i%255}.{i%255}', 'timestamp': time.time()}


def hmac_sig(secret: str, body: bytes, ts: str) -> str:
    return hmac.new(secret.encode('utf-8'), msg=ts.encode('utf-8') + b'.' + body, digestmod=hashlib.sha256).hexdigest()


def drain_queue_to_hopgraph(limit: int = 100000):
    drained = 0
    while drained < limit:
        try:
            item = EVENT_QUEUE.get_nowait()
        except Exception:
            break
        # item expected: {'integrator_id':..., 'events':[...]} for xdr worker
        for ev in item.get('events', []) if isinstance(item.get('events'), list) else []:
            try:
                GLOBAL_HOPGRAPH.ingest_event(ev)
            except Exception:
                pass
        drained += 1
    return drained


def main(batches=200, batch_size=100, integrator_id='stress-test'):
    client = TestClient(app)
    # register integrator
    r = client.post(f'/api/v1/integrations/xdr/register?integrator_id={integrator_id}')
    if r.status_code != 200:
        print('register failed', r.status_code, r.text); return
    secret = r.json().get('secret')
    print('Registered integrator, secret len=', len(secret or ''))

    t0 = time.time()
    sent = 0
    for b in range(batches):
        events = [make_event(b*batch_size + i) for i in range(batch_size)]
        body = json.dumps({'events': events}).encode('utf-8')
        ts = str(int(time.time()))
        sig = hmac_sig(secret, body, ts)
        headers = {
            'X-Integrator-ID': integrator_id,
            'X-Signature': sig,
            'X-Timestamp': ts,
            'Content-Type': 'application/json'
        }
        r = client.post('/api/v1/integrations/xdr/webhook', data=body, headers=headers)
        if r.status_code not in (200, 202):
            print('batch failed', b, r.status_code, r.text)
        sent += 1
        if (b+1) % 20 == 0:
            drained = drain_queue_to_hopgraph()
            print(f'batch {b+1}/{batches} sent; drained {drained} queued batches so far')

    total_time = time.time() - t0
    print('Sent batches:', sent, 'in', total_time, 's')
    # final drain
    drained = drain_queue_to_hopgraph()
    print('Final drained', drained)


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--batches', type=int, default=200)
    p.add_argument('--batch-size', type=int, default=100)
    args = p.parse_args()
    main(batches=args.batches, batch_size=args.batch_size)
