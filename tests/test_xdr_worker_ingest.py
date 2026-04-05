import time
import json
import hashlib
import hmac
from fastapi.testclient import TestClient

from src.api.app import create_app
app = create_app({'mode': 'test'})
from src.graph.hopgraph import GLOBAL_HOPGRAPH
from src.api import integrations_endpoints as _ix
from src.api.runtime_state import drain_event_queue_for_tests


def make_sig(secret: str, body: bytes, ts: int) -> str:
    mac = hmac.new(secret.encode('utf-8'), msg=str(ts).encode('utf-8') + b'.' + body, digestmod=hashlib.sha256)
    return mac.hexdigest()


def test_xdr_worker_ingest_single_batch():
    client = TestClient(app)
    integrator_id = 'itest-1'
    r = client.post(f'/api/v1/integrations/xdr/register?integrator_id={integrator_id}')
    assert r.status_code == 200
    secret = r.json().get('secret')
    assert secret

    # Clear HopGraph to make test deterministic (best-effort)
    try:
        GLOBAL_HOPGRAPH.nodes.clear()
        GLOBAL_HOPGRAPH.adj.clear()
    except Exception:
        pass

    event = {
        'id': 'apt-test-1',
        'timestamp': int(time.time()),
        'host': 'host-A',
        'process': 'evil.exe',
        'pid': 1234,
        'src_ip': '10.0.0.1',
        'dst_ip': '8.8.8.8',
        'domain': 'mal.bad',
        'file_hash': 'DEADBEEF1234'
    }

    body = json.dumps({'events': [event]}).encode('utf-8')
    ts = int(time.time())
    sig = make_sig(secret, body, ts)
    headers = {
        'X-Integrator-ID': integrator_id,
        'X-Signature': sig,
        'X-Timestamp': str(ts),
        'Content-Type': 'application/json'
    }

    r2 = client.post('/api/v1/integrations/xdr/webhook', content=body, headers=headers)
    assert r2.status_code == 200

    # Ensure background pipeline processes posted event (test helper drains queue)
    try:
        drain_event_queue_for_tests()
    except Exception:
        # fallback: small sleep if helper not available
        import time as _t; _t.sleep(0.25)

    # Poll recent ingestion ring for the event id (more robust than scanning nodes)
    status = _ix.wait_for_recent_ingest('apt-test-1', timeout=4.0)
    assert status.get('found'), f"ingest not seen within timeout; recent={status.get('recent')}"

    # Verify explain_chain returns a chain for the process node
    proc_node = f"process:{event['process'].lower()}:{event['pid']}"
    res = GLOBAL_HOPGRAPH.explain_chain(proc_node, max_depth=3)
    assert isinstance(res, dict)
    assert res.get('chains') is not None
    assert len(res.get('chains') or []) >= 1
