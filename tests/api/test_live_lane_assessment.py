import os

import pytest
from fastapi.testclient import TestClient


API_KEY = os.environ.get('TEST_API_KEY', 'devkey123')


@pytest.fixture(scope='module')
def client():
    os.environ.setdefault('TEST_HELPERS_ENABLED', '1')
    os.environ.setdefault('PLATFORM_LITE_INIT', '1')
    os.environ.setdefault('DISABLE_DB', '1')
    from src.api.app import app
    return TestClient(app)


def _headers():
    return {'x-api-key': API_KEY, 'x-tenant-id': 'default'}


def test_live_lane_assessment_round_trip_includes_email_and_connector_provenance(monkeypatch, client):
    def _fetch_cloudtrail(self, start_time=None):
        return iter([
            {
                'source': 'cloudtrail',
                'id': 'aws-evt-1',
                'ts': '2026-04-10T00:00:00Z',
                'account_id': '123456789012',
                'principal_arn': 'arn:aws:iam::123456789012:user/ceo@shopsquire.example',
                'action': 'ConsoleLogin',
                'ip': '203.0.113.99',
                'resource': 'prod-finance-bucket',
            }
        ])

    def _fetch_signins(self, since_ts=None):
        return iter([
            {
                'source': 'azure_entra_signin',
                'id': 'az-evt-1',
                'actor': 'ceo@shopsquire.example',
                'userPrincipalName': 'ceo@shopsquire.example',
                'ipAddress': '203.0.113.99',
                'ts': '2026-04-10T00:05:00Z',
                'appDisplayName': 'Microsoft 365 Exchange Online',
            }
        ])

    def _fetch_okta(self, since_ts):
        return [
            {
                'uuid': 'okta-evt-1',
                'published': '2026-04-10T00:07:00Z',
                'eventType': 'user.authentication.failed',
                'actor': {'alternateId': 'ceo@shopsquire.example'},
                'client': {'ipAddress': '203.0.113.99'},
                'target': [{'displayName': 'ceo@shopsquire.example'}],
            }
        ]

    async def _poll_sailpoint(self):
        return [
            {
                'id': 'sp-evt-1',
                'created': '2026-04-10T00:09:00Z',
                'type': 'privilege-change',
                'actor': {'name': 'ceo@shopsquire.example'},
                'target': {'name': 'Finance-Approver'},
                'operation': 'privilege-change',
            }
        ]

    async def _mime_execute(self, domain, entity, window=None, context=None):
        return {
            'events': [
                {
                    'id': 'mime-1',
                    'Datetime': '2026-04-10T00:01:00Z',
                    'Sender': 'accounts@ingramfake.com.au',
                    'Recipients': ['ceo@shopsquire.example'],
                    'Subject': 'Updated invoice for acquisition deposit',
                    'Act': 'HOLD',
                    'Threat': 'supplier_impersonation',
                }
            ]
        }

    async def _proof_execute(self, domain, entity, window=None, context=None):
        return {
            'events': [
                {
                    'id': 'pp-1',
                    'clickTime': '2026-04-10T00:02:00Z',
                    'recipient': 'ceo@shopsquire.example',
                    'sender': 'accounts@ingramfake.com.au',
                    'subject': 'Updated invoice for acquisition deposit',
                    'threatsInfoMap': [{'threatType': 'credential_phish'}],
                }
            ]
        }

    from src.api.routes.connectors import (
        CloudTrailConnector as _CloudTrail,
        EntraIDConnector as _EntraID,
        MimecastConnector as _Mimecast,
        OktaIAMCollector as _Okta,
        ProofpointConnector as _Proofpoint,
        SailPointCollector as _SailPoint,
    )

    monkeypatch.setattr(_CloudTrail, 'fetch_events', _fetch_cloudtrail)
    monkeypatch.setattr(_EntraID, 'fetch_signins', _fetch_signins)
    monkeypatch.setattr(_Okta, 'fetch_events', _fetch_okta)
    monkeypatch.setattr(_SailPoint, 'poll_events', _poll_sailpoint)
    monkeypatch.setattr(_Mimecast, 'execute', _mime_execute)
    monkeypatch.setattr(_Proofpoint, 'execute', _proof_execute)

    assert client.put(
        '/api/v1/connectors/default/azure/entra_signin/config',
        headers=_headers(),
        json={'config': {'tenant_id': 'tenant-123', 'client_id': 'cid', 'client_secret': 'secret', 'auth_mode': 'client_secret'}},
    ).status_code == 200
    assert client.put(
        '/api/v1/connectors/default/okta/okta/config',
        headers=_headers(),
        json={'config': {'org_url': 'https://acme.okta.com', 'api_token': 'ssws-123'}},
    ).status_code == 200
    assert client.put(
        '/api/v1/connectors/default/sailpoint/sailpoint/config',
        headers=_headers(),
        json={'config': {'base_url': 'https://tenant.api.identitynow.com', 'client_id': 'cid', 'client_secret': 'secret'}},
    ).status_code == 200
    assert client.put(
        '/api/v1/connectors/default/email/mimecast/config',
        headers=_headers(),
        json={'config': {'client_id': 'cid', 'client_secret': 'secret', 'token_url': 'https://mimecast.example/token'}},
    ).status_code == 200
    assert client.put(
        '/api/v1/connectors/default/email/proofpoint/config',
        headers=_headers(),
        json={'config': {'client_id': 'cid', 'client_secret': 'secret', 'token_url': 'https://proofpoint.example/token'}},
    ).status_code == 200

    for route in (
        '/api/v1/connectors/default/aws/cloudtrail/poll',
        '/api/v1/connectors/default/azure/entra_signin/poll',
        '/api/v1/connectors/default/okta/okta/poll',
        '/api/v1/connectors/default/sailpoint/sailpoint/poll',
        '/api/v1/connectors/default/email/mimecast/poll',
        '/api/v1/connectors/default/email/proofpoint/poll',
    ):
        resp = client.post(route, headers=_headers(), json={'since_ts': 0})
        assert resp.status_code == 200, resp.text

    live = client.post(
        '/api/v1/connectors/default/assessment/live_lane',
        headers=_headers(),
        json={
            'providers': ['aws', 'azure', 'okta', 'sailpoint', 'email'],
            'connectors': ['cloudtrail', 'entra_signin', 'okta', 'sailpoint', 'mimecast', 'proofpoint'],
            'limit_per_lane': 10,
            'auto_llm': False,
            'include_email': True,
        },
    )
    assert live.status_code == 200, live.text
    assessment = live.json()
    assert assessment.get('assessment_id')
    assert assessment.get('intake_mode') == 'live'
    assert assessment.get('connector_health_snapshot')

    rows = assessment.get('rows') or assessment.get('llm_rows') or []
    sources = {str(row.get('source_kind') or row.get('source') or '').lower() for row in rows}
    assert 'mimecast' in sources
    assert 'proofpoint' in sources
    assert 'okta' in sources
    assert 'sailpoint' in sources

    cluster_state = assessment.get('cluster_reasoning_state') or {}
    assert cluster_state.get('primary_cluster_id')
    cluster_id = cluster_state['primary_cluster_id']

    detail = client.get(
        f"/api/v1/assessments/{assessment['assessment_id']}/clusters/{cluster_id}",
        headers=_headers(),
    )
    assert detail.status_code == 200, detail.text
    payload = detail.json()
    provider_context = (payload.get('cluster_detail') or {}).get('provider_context') or {}
    connector_status = provider_context.get('connector_status') or []
    assert connector_status
    assert any(str(item.get('connector') or '').startswith('email:') for item in connector_status) or provider_context.get('email_evidence')
    assert provider_context.get('email_evidence')
    freshness = provider_context.get('connector_freshness') or {}
    assert 'available' in freshness
    assert 'missing_sources' in freshness
