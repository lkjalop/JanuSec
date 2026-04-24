import asyncio

from fastapi import FastAPI
from fastapi.testclient import TestClient


def test_streaming_ingest_rejects_missing_api_key(monkeypatch):
    monkeypatch.delenv('JANUSEC_DEV_MODE', raising=False)
    monkeypatch.delenv('TEST_HELPERS_ENABLED', raising=False)
    monkeypatch.setenv('API_KEY', 'secret-test-key')

    from src.api.streaming_endpoints import ingest_router

    app = FastAPI()
    app.include_router(ingest_router)
    client = TestClient(app)

    missing = client.post('/api/v1/stream/sessions', json={'org': 'acme'})
    assert missing.status_code == 401

    wrong = client.post(
        '/api/v1/stream/sessions',
        json={'org': 'acme'},
        headers={'X-API-Key': 'wrong'},
    )
    assert wrong.status_code == 401

    ok = client.post(
        '/api/v1/stream/sessions',
        json={'org': 'acme'},
        headers={'X-API-Key': 'secret-test-key'},
    )
    assert ok.status_code == 201


def test_nested_account_extraction_ignores_raw_actor_dict_and_group_target():
    from src.api.deep_analyze_endpoints import _extract_accounts_backend

    row = {
        'userIdentity': {
            'userName': 'aws-user',
            'arn': 'arn:aws:iam::123:user/aws-user',
        },
        'actor': {
            'alternateId': 'okta.user@example.com',
            'displayName': 'Okta User',
        },
        'target': [
            {'type': 'Group', 'alternateId': 'ignored-group@example.com'},
            {'type': 'AppUser', 'alternateId': 'appuser@example.com'},
            {'type': 'SystemUser', 'displayName': 'System User'},
        ],
        'initiatedBy': {
            'user': {'userPrincipalName': 'entra.user@example.com'},
        },
    }

    accounts = _extract_accounts_backend(row)
    assert 'okta.user@example.com' in accounts
    assert 'appuser@example.com' in accounts
    assert 'System User' in accounts
    assert 'entra.user@example.com' in accounts
    assert 'ignored-group@example.com' not in accounts
    assert not any(str(account).startswith("{'alternateId'") for account in accounts)


def test_vendor_egress_ip_suppressed_without_ioc(monkeypatch):
    from src.api.deep_analyze_endpoints import _extract_attacker_ips
    from src.integrations.threat_intel_client import CLIENT

    ip = '104.16.10.20'
    CLIENT.ip_set.discard(ip)
    monkeypatch.setattr(CLIENT, 'allow_ips', set(), raising=False)

    assert ip not in _extract_attacker_ips({'src_ip': ip})


def test_vendor_egress_ip_allowed_when_ioc_confirmed(monkeypatch):
    from src.api.deep_analyze_endpoints import _extract_attacker_ips
    from src.integrations.threat_intel_client import CLIENT

    ip = '104.16.10.20'
    CLIENT.ip_set.add(ip)
    monkeypatch.setattr(CLIENT, 'allow_ips', set(), raising=False)

    try:
        assert ip in _extract_attacker_ips({'src_ip': ip})
    finally:
        CLIENT.ip_set.discard(ip)


def test_vendor_egress_ip_not_used_as_external_cluster_pivot(monkeypatch):
    from src.api.deep_analyze_endpoints import _normalize_assessment_rows
    from src.integrations.threat_intel_client import CLIENT

    ip = '104.16.10.20'
    CLIENT.ip_set.discard(ip)
    monkeypatch.setattr(CLIENT, 'allow_ips', set(), raising=False)

    normalized = _normalize_assessment_rows({
        'rows': [{'row_index': 1, 'src_ip': ip, 'user': 'alice@example.com'}],
    })

    assert normalized[0]['external_ips'] == []


def test_ioc_confirmed_vendor_ip_kept_as_external_cluster_pivot(monkeypatch):
    from src.api.deep_analyze_endpoints import _normalize_assessment_rows
    from src.integrations.threat_intel_client import CLIENT

    ip = '104.16.10.20'
    CLIENT.ip_set.add(ip)
    monkeypatch.setattr(CLIENT, 'allow_ips', set(), raising=False)

    try:
        normalized = _normalize_assessment_rows({
            'rows': [{'row_index': 1, 'src_ip': ip, 'user': 'alice@example.com'}],
        })
        assert normalized[0]['external_ips'] == [ip]
    finally:
        CLIENT.ip_set.discard(ip)


def test_system_account_and_vendor_ip_do_not_form_cluster_pivot(monkeypatch):
    from src.api.deep_analyze_endpoints import _build_correlation_clusters, _normalize_assessment_rows
    from src.integrations.threat_intel_client import CLIENT

    ip = '13.107.4.50'
    CLIENT.ip_set.discard(ip)
    monkeypatch.setattr(CLIENT, 'allow_ips', set(), raising=False)
    normalized = _normalize_assessment_rows({
        'rows': [
            {'row_index': 1, 'src_ip': ip, 'user': 'SYSTEM', 'event_name': 'NetworkConnect', 'timestamp': '2026-03-01T10:00:00Z'},
            {'row_index': 2, 'src_ip': ip, 'user': 'SYSTEM', 'event_name': 'NetworkConnect', 'timestamp': '2026-03-01T10:01:00Z'},
        ],
    })

    assert all(row['external_ips'] == [] for row in normalized)
    clusters, _ = _build_correlation_clusters(normalized)
    assert clusters == []


def test_open_streaming_session_recovers_rows_and_clusters(tmp_path, monkeypatch):
    monkeypatch.setenv('JANUSEC_SESSIONS_DB', str(tmp_path / 'streaming_sessions.db'))
    monkeypatch.setenv('JANUSEC_STREAMING_SNAPSHOT_DIR', str(tmp_path / 'snapshots'))

    import src.pipeline.streaming_ingest as si

    si._SESSIONS.clear()
    session = si.get_or_create_session('stream-test-001', org='acme')
    asyncio.run(session.ingest([
        {
            'actor': {'alternateId': 'finance@example.com'},
            'client': {'ipAddress': '45.153.160.100'},
            'eventType': 'user.authentication.failed',
            'timestamp': '2026-03-01T10:00:00Z',
            'severity': 'high',
        },
        {
            'actor': {'alternateId': 'finance@example.com'},
            'client': {'ipAddress': '45.153.160.100'},
            'eventType': 'user.mfa.attempt_bypass',
            'timestamp': '2026-03-01T10:01:00Z',
            'severity': 'high',
        },
    ], source='okta'))
    si._persist_session_meta(session)

    si._SESSIONS.clear()
    assert si.recover_open_sessions() == 1

    recovered = si.get_session('stream-test-001')
    assert recovered is not None
    snapshot = recovered.snapshot()
    assert snapshot['total_ingested'] == 2
    assert snapshot['cluster_count'] >= 1
    assert snapshot['correlation_clusters'][0]['row_refs']

    si._SESSIONS.clear()
