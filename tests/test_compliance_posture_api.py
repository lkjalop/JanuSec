from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi.testclient import TestClient

from src.api.app import app


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")


def test_posture_summary_tenant_scoped(tmp_path, monkeypatch):
    p = tmp_path / 'posture.jsonl'
    rows = [
        {'ts': 1, 'tenant_id': 't1', 'id': 'a', 'type': 'cloud:public_bucket', 'resource': 's3://x', 'severity': 'critical'},
        {'ts': 2, 'tenant_id': 't1', 'id': 'b', 'type': 'iam:key_no_mfa', 'resource': 'user:abc', 'severity': 'low'},
        {'ts': 3, 'tenant_id': 't2', 'id': 'c', 'type': 'k8s:privileged_pod', 'resource': 'ns/pod', 'severity': 'high'},
        {'ts': 4, 'tenant_id': 't1', 'id': 'd', 'type': 'cloud:sg_open_0_0_0_0', 'resource': 'sg-1', 'severity': 'high'},
    ]
    _write_jsonl(p, rows)
    monkeypatch.setenv('POSTURE_LOG_PATH', str(p))
    client = TestClient(app)
    r = client.get('/api/v1/compliance/posture', headers={'X-Tenant-ID': 't1', 'x-api-key': 'devkey123'})
    assert r.status_code == 200
    j = r.json()
    # t1 has 3 rows
    assert j['total'] == 3
    sev = j['severity']
    assert sev['critical'] == 1
    assert sev['high'] == 1
    # risk_score should be positive given critical/high present
    assert j['risk_score'] >= 3.0

