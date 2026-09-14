"""Tests for E9 (kill-chain phase tagging), E10 (sticky notes), E12 (repeat entities).
E11 (IOC export) is client-side JS — no server test needed.
E13 (persona narrative button) wraps existing tier2 endpoint — no new server code.
"""
from __future__ import annotations

import os
os.environ.setdefault('JANUSEC_DISABLE_T1_PREFILL', '1')

import pytest
from fastapi.testclient import TestClient


# ── Fixtures ───────────────────────────────────────────────────────────────────

ASSESSMENT_ID = 'test-e9e13-001'

CLUSTER_A = {
    'cluster_id': 'cluster-a',
    'severity': 'high',
    'verdict': 'CONFIRMED',
    'row_refs': [0, 1, 2],
}

CLUSTER_B = {
    'cluster_id': 'cluster-b',
    'severity': 'medium',
    'verdict': 'LIKELY REAL',
    'row_refs': [3, 4],
}

ROWS = [
    {
        'row_index': 0, 'severity': 'high', '_source': 'okta',
        'user': 'alice@corp.com', 'src_ip': '185.1.2.3',
        'mitre_technique': 'T1110', 'description': 'Credential spray',
        'timestamp': '2024-03-15T10:00:00Z',
    },
    {
        'row_index': 1, 'severity': 'high', '_source': 'azure_entra',
        'user': 'alice@corp.com', 'src_ip': '185.1.2.3',
        'mitre_technique': 'T1078', 'description': 'Successful login with valid creds',
        'timestamp': '2024-03-15T10:05:00Z',
    },
    {
        'row_index': 2, 'severity': 'medium', '_source': 'endpoint',
        'hostname': 'WORKSTATION-1', 'user': 'alice@corp.com',
        'mitre_technique': 'T1059', 'description': 'Powershell execution',
        'timestamp': '2024-03-15T10:10:00Z',
    },
    {
        'row_index': 3, 'severity': 'medium', '_source': 'okta',
        'user': 'bob@corp.com', 'src_ip': '45.12.200.88',
        'description': 'Suspicious login',
        'timestamp': '2024-03-15T11:00:00Z',
    },
    {
        'row_index': 4, 'severity': 'low', '_source': 'azure_net',
        'src_ip': '45.12.200.88', 'dst_ip': '10.1.1.5',
        'description': 'Outbound connection',
        'timestamp': '2024-03-15T11:05:00Z',
    },
]

TEST_ASSESSMENT = {
    'assessment_id': ASSESSMENT_ID,
    'normalized_rows': ROWS,
    'correlation_clusters': [CLUSTER_A, CLUSTER_B],
    'source_count': 3,
}


@pytest.fixture(autouse=True)
def inject_assessment(monkeypatch):
    """Inject test assessment into REPORT_STORE before each test."""
    try:
        from src.api.deep_analyze_endpoints import REPORT_STORE
        REPORT_STORE[ASSESSMENT_ID] = TEST_ASSESSMENT
        yield
        REPORT_STORE.pop(ASSESSMENT_ID, None)
    except Exception:
        yield


@pytest.fixture
def client():
    try:
        from src.api.breach_endpoints import router
        from fastapi import FastAPI
        app = FastAPI()
        app.include_router(router)
        return TestClient(app)
    except Exception as exc:
        pytest.skip(f'Could not build test client: {exc}')


# ── E9: Kill-chain phase tagging ──────────────────────────────────────────────

class TestKillChainPhaseUtil:
    def test_known_technique_returns_correct_phase(self):
        from src.api.breach_endpoints import tag_kill_chain_phase
        row = {'mitre_technique': 'T1110'}
        assert tag_kill_chain_phase(row) == 'Credential Access'

    def test_initial_access_technique(self):
        from src.api.breach_endpoints import tag_kill_chain_phase
        row = {'mitre_technique': 'T1078'}
        assert tag_kill_chain_phase(row) == 'Initial Access'

    def test_execution_technique(self):
        from src.api.breach_endpoints import tag_kill_chain_phase
        row = {'mitre_technique': 'T1059'}
        assert tag_kill_chain_phase(row) == 'Execution'

    def test_sub_technique_uses_base(self):
        from src.api.breach_endpoints import tag_kill_chain_phase
        row = {'mitre_technique': 'T1110.003'}  # Password Spray sub-technique
        assert tag_kill_chain_phase(row) == 'Credential Access'

    def test_unknown_technique_returns_unknown(self):
        from src.api.breach_endpoints import tag_kill_chain_phase
        row = {'mitre_technique': 'T9999'}
        assert tag_kill_chain_phase(row) == 'Unknown'

    def test_no_mitre_field_returns_unknown(self):
        from src.api.breach_endpoints import tag_kill_chain_phase
        row = {'description': 'something happened'}
        assert tag_kill_chain_phase(row) == 'Unknown'

    def test_list_mitre_field(self):
        from src.api.breach_endpoints import tag_kill_chain_phase
        row = {'mitre_technique': ['T1110', 'T1078']}
        result = tag_kill_chain_phase(row)
        assert result in ('Credential Access', 'Initial Access')

    def test_technique_id_field_fallback(self):
        from src.api.breach_endpoints import tag_kill_chain_phase
        row = {'technique_id': 'T1021'}
        assert tag_kill_chain_phase(row) == 'Lateral Movement'


class TestTimelineEndpoint:
    def test_timeline_returns_tagged_rows(self, client):
        r = client.get(f'/api/v1/assessments/{ASSESSMENT_ID}/clusters/cluster-a/timeline')
        assert r.status_code == 200
        data = r.json()
        assert data['total'] == 3
        assert all('kill_chain_phase' in row for row in data['rows'])

    def test_timeline_rows_sorted_by_timestamp(self, client):
        r = client.get(f'/api/v1/assessments/{ASSESSMENT_ID}/clusters/cluster-a/timeline')
        rows = r.json()['rows']
        # Row 0 should come before row 2 (timestamps are in order)
        indices = [row['row_index'] for row in rows if row['row_index'] is not None]
        assert indices.index(0) < indices.index(2)

    def test_timeline_phases_grouped_correctly(self, client):
        r = client.get(f'/api/v1/assessments/{ASSESSMENT_ID}/clusters/cluster-a/timeline')
        phases = {p['phase']: p['rows'] for p in r.json()['phases']}
        assert 'Credential Access' in phases
        assert 'Initial Access' in phases
        assert 'Execution' in phases

    def test_timeline_404_on_missing_cluster(self, client):
        r = client.get(f'/api/v1/assessments/{ASSESSMENT_ID}/clusters/no-such-cluster/timeline')
        assert r.status_code == 404

    def test_timeline_404_on_missing_assessment(self, client):
        r = client.get('/api/v1/assessments/no-such-aid/clusters/cluster-a/timeline')
        assert r.status_code == 404


# ── E10: Analyst sticky notes ─────────────────────────────────────────────────

class TestAnalystNotes:
    def test_patch_notes_returns_ok(self, client):
        r = client.patch(
            f'/api/v1/assessments/{ASSESSMENT_ID}/clusters/cluster-a/notes',
            json={'notes': 'Confirmed with alice — was a pentest.', 'analyst_id': 'analyst1'},
        )
        assert r.status_code == 200
        assert r.json()['status'] == 'ok'

    def test_patch_notes_persisted_to_cluster(self, client):
        from src.api.deep_analyze_endpoints import REPORT_STORE
        client.patch(
            f'/api/v1/assessments/{ASSESSMENT_ID}/clusters/cluster-a/notes',
            json={'notes': 'Test note content', 'analyst_id': 'analyst2'},
        )
        a = REPORT_STORE.get(ASSESSMENT_ID, {})
        cluster = next(c for c in a.get('correlation_clusters', []) if c['cluster_id'] == 'cluster-a')
        assert cluster.get('analyst_notes', {}).get('text') == 'Test note content'

    def test_patch_empty_notes_allowed(self, client):
        r = client.patch(
            f'/api/v1/assessments/{ASSESSMENT_ID}/clusters/cluster-a/notes',
            json={'notes': ''},
        )
        assert r.status_code == 200

    def test_patch_notes_404_on_bad_assessment(self, client):
        r = client.patch(
            '/api/v1/assessments/bad-id/clusters/cluster-a/notes',
            json={'notes': 'hello'},
        )
        assert r.status_code == 404


# ── E11: IOC bundle (server endpoint) ────────────────────────────────────────

class TestIocBundle:
    def test_iocs_returns_entities(self, client):
        r = client.get(f'/api/v1/assessments/{ASSESSMENT_ID}/clusters/cluster-a/iocs')
        assert r.status_code == 200
        data = r.json()
        assert 'users' in data and 'ips' in data and 'hosts' in data
        assert 'alice@corp.com' in data['users']
        assert '185.1.2.3' in data['ips']

    def test_iocs_cluster_b_different_entities(self, client):
        r = client.get(f'/api/v1/assessments/{ASSESSMENT_ID}/clusters/cluster-b/iocs')
        data = r.json()
        assert 'bob@corp.com' in data['users']
        # alice should NOT appear in cluster-b
        assert 'alice@corp.com' not in data['users']

    def test_iocs_includes_metadata(self, client):
        r = client.get(f'/api/v1/assessments/{ASSESSMENT_ID}/clusters/cluster-a/iocs')
        data = r.json()
        assert data['cluster_id'] == 'cluster-a'
        assert data['verdict'] == 'CONFIRMED'
        assert 'exported_at' in data


# ── E12: Repeat entity detection ─────────────────────────────────────────────

class TestRepeatEntities:
    def test_no_matches_when_only_one_assessment(self, client):
        r = client.get(f'/api/v1/assessments/{ASSESSMENT_ID}/clusters/cluster-a/repeat-entities')
        assert r.status_code == 200
        data = r.json()
        assert data['match_count'] == 0
        assert data['matches'] == []

    def test_finds_match_across_assessments(self, client, monkeypatch):
        from src.api.deep_analyze_endpoints import REPORT_STORE
        # Inject a past assessment sharing alice@corp.com
        past_assessment = {
            'assessment_id': 'past-001',
            'normalized_rows': [
                {'row_index': 0, 'user': 'alice@corp.com', 'src_ip': '10.0.0.1'},
            ],
            'correlation_clusters': [{
                'cluster_id': 'cluster-past-1',
                'severity': 'high',
                'verdict': 'CONFIRMED',
                'row_refs': [0],
            }],
        }
        REPORT_STORE['past-001'] = past_assessment
        try:
            r = client.get(f'/api/v1/assessments/{ASSESSMENT_ID}/clusters/cluster-a/repeat-entities')
            data = r.json()
            assert data['match_count'] >= 1
            match = data['matches'][0]
            assert 'alice@corp.com' in match['shared_entities']
            assert match['past_assessment_id'] == 'past-001'
        finally:
            REPORT_STORE.pop('past-001', None)

    def test_does_not_match_self(self, client):
        r = client.get(f'/api/v1/assessments/{ASSESSMENT_ID}/clusters/cluster-a/repeat-entities')
        data = r.json()
        for m in data['matches']:
            assert m['past_assessment_id'] != ASSESSMENT_ID

    def test_current_entity_count_populated(self, client):
        r = client.get(f'/api/v1/assessments/{ASSESSMENT_ID}/clusters/cluster-a/repeat-entities')
        data = r.json()
        # cluster-a has alice@corp.com, 185.1.2.3, WORKSTATION-1
        assert data['current_entity_count'] >= 2
