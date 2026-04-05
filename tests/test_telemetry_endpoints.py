from __future__ import annotations

import os
import json
from fastapi.testclient import TestClient
from src.api.app import app


def _override_scopes(*args, **kwargs):
    # test-mode bypass for require_scopes dependency used in endpoints
    return None


def test_telemetry_diagnose_and_execute_remediation(monkeypatch):
    # Ensure PLATFORM_LITE_INIT so endpoints skip strict scopes
    monkeypatch.setenv('PLATFORM_LITE_INIT', '1')
    client = TestClient(app)

    # Prepare missing items payload
    items = [
        {'source': 'proofpoint', 'reason': 'no_recent_fetch'},
        {'source': 'okta', 'reason': 'expired_token'},
    ]

    headers = {'x-api-key': 'testkey123'}
    resp = client.post('/api/v1/telemetry/diagnose?kwargs=', json={'items': items}, headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert 'suggestions' in body and body['count'] == len(body['suggestions'])
    # suggestions should reference suggested_action keys
    acts = {s.get('suggested_action') for s in body['suggestions']}
    assert 'restart_collector' in acts or 'refresh_api_token' in acts

    # Execute a dry-run remediation for restart_collector
    exec_resp = client.post('/api/v1/telemetry/execute_remediation?kwargs=', json={'action': 'restart_collector', 'collector': 'proofpoint', 'dry_run': True}, headers=headers)
    assert exec_resp.status_code == 200, exec_resp.text
    exec_body = exec_resp.json()
    assert exec_body.get('ok') is True
    assert exec_body.get('result', {}).get('status') == 'dry_run'

    # Execute refresh_api_token dry-run
    exec_resp2 = client.post('/api/v1/telemetry/execute_remediation?kwargs=', json={'action': 'refresh_api_token', 'connector': 'okta', 'dry_run': True}, headers=headers)
    assert exec_resp2.status_code == 200, exec_resp2.text
    exec_body2 = exec_resp2.json()
    assert exec_body2.get('ok') is True
    assert exec_body2.get('result', {}).get('status') == 'dry_run'
