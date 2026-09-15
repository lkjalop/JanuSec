#!/usr/bin/env python3
"""Post dump/janusec_batch1.json to XDR webhook and Zeek stream-ingest endpoints
using the FastAPI TestClient. Prints responses and HopGraph edge counts.
"""
import json
import time
import hmac
import hashlib
import sys
from pathlib import Path

# Ensure project root is on sys.path so `src` imports resolve when run as a script
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

from src.api.app import app
from src.graph.hopgraph import GLOBAL_HOPGRAPH


def hmac_sig(secret: str, body: bytes, ts: int) -> str:
    mac = hmac.new(secret.encode('utf-8'), msg=str(ts).encode('utf-8') + b'.' + body, digestmod=hashlib.sha256)
    return mac.hexdigest()


def edges_count() -> int:
    return sum(len(v) for v in GLOBAL_HOPGRAPH.adj.values())


def main():
    p = Path('dump/janusec_batch1.json')
    if not p.exists():
        print('Missing', p)
        return

    payload = json.loads(p.read_text(encoding='utf-8'))
    orig_body = p.read_bytes()
    events = payload.get('events') or []

    client = TestClient(app)

    print('Edges before:', edges_count())
    # print a sample explain before posting
    sample_host = None
    if events:
        sample_host = events[0].get('host')
    if sample_host:
        try:
            print('\nExplain before for', sample_host)
            import json as _json
            ex = GLOBAL_HOPGRAPH.explain_chain(start=f'host:{sample_host}', max_depth=3, beam_width=6, top_k=3)
            print(_json.dumps(ex, indent=2)[:2000])
        except Exception:
            pass

    # Register an XDR integrator to obtain a secret
    integrator_id = payload.get('tenant_id') or payload.get('tenant') or 'cybstash_test'
    print('Registering integrator:', integrator_id)
    r = client.post(f'/api/v1/integrations/xdr/register?integrator_id={integrator_id}')
    try:
        reg = r.json()
    except Exception:
        reg = {'status_code': r.status_code, 'text': r.text}
    print('Register response:', r.status_code, reg)
    secret = reg.get('secret') if isinstance(reg, dict) else None
    if not secret:
        print('No secret returned, cannot post to XDR webhook')
    else:
        ts = int(time.time())
        sig = hmac_sig(secret, orig_body, ts)
        headers = {
            'X-Integrator-ID': integrator_id,
            'X-Timestamp': str(ts),
            'X-Signature': sig,
            'Content-Type': 'application/json',
        }
        print('Posting full batch to XDR webhook...')
        rx = client.post('/api/v1/integrations/xdr/webhook', data=orig_body, headers=headers)
        try:
            print('XDR webhook ->', rx.status_code, rx.json())
        except Exception:
            print('XDR webhook ->', rx.status_code, rx.text[:400])

    # Post events array to Zeek stream ingest (normalize to JSON array)
    if events:
        zb = json.dumps(events).encode('utf-8')
        print(f'Posting {len(events)} events to zeek-json ingest...')
        rz = client.post('/api/v1/ingest/zeek-json', data=zb, headers={'Content-Type': 'application/json', 'X-Tenant-Id': integrator_id})
        try:
            print('Zeek ingest ->', rz.status_code, rz.json())
        except Exception:
            print('Zeek ingest ->', rz.status_code, rz.text[:400])
    else:
        print('No events array present; skipping zeek-json post')

    # Wait briefly for any background processing
    # Drain in-process EVENT_QUEUE so TestClient-enqueued items get processed
    try:
        from .drain_event_queue import main as _drain_main
        # run with a small limit to avoid long blocking
        _drain_main(limit=500)
    except Exception:
        # fallback to brief sleep if drain helper unavailable
        time.sleep(1.0)
    print('Edges after:', edges_count())


if __name__ == '__main__':
    main()
