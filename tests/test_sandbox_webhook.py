import json
import os
import hmac
import hashlib
from fastapi.testclient import TestClient

from src.api.app import app


def test_sandbox_webhook_signature(tmp_path):
    provider = 'testprov'
    cfg_dir = tmp_path / 'data' / 'integrations'
    cfg_dir.mkdir(parents=True)
    cfg_path = cfg_dir / f'{provider}.json'
    secret = 'shh-its-a-secret'
    cfg = {'webhook_secret': secret, 'webhook_secret_header': 'X-Sandbox-Signature'}
    with open(cfg_path, 'w', encoding='utf-8') as fh:
        json.dump(cfg, fh)

    # point app to temporary data dir by monkeypatching path resolution
    # simple approach: copy file into expected location
    dest_dir = os.path.join('data', 'integrations')
    os.makedirs(dest_dir, exist_ok=True)
    with open(os.path.join(dest_dir, f'{provider}.json'), 'w', encoding='utf-8') as fh:
        json.dump(cfg, fh)

    client = TestClient(app)
    payload = {'task_id': 'abc', 'verdict': 'suspicious'}
    body = json.dumps(payload).encode('utf-8')
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    resp = client.post(f'/api/v1/sandbox/webhook/{provider}', data=body, headers={'X-Sandbox-Signature': sig, 'Content-Type': 'application/json'})
    assert resp.status_code == 200
    assert resp.json().get('status') == 'ok'
