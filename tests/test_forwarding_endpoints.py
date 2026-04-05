import time

from starlette.testclient import TestClient

from src.api.app import create_app

app = create_app({'mode': 'test'})


def _sample_rows():
    now = time.time()
    return [
        {
            'event_id': 'evt-high',
            'triage_score': 0.92,
            'confidence': 0.88,
            'evidence_refs': [{'type': 'file', 'value': 'a.dll'}],
            'novelty_score': 0.7,
            'ingested_ts': now - 120,
            'persona_tags': ['executive', 'soc_analyst'],
            'decision_gate': {'requires_budget': True},
            'impact_score': 0.9,
        },
        {
            'event_id': 'evt-med',
            'triage_score': 0.55,
            'confidence': 0.5,
            'evidence_refs': [],
            'novelty_score': 0.2,
            'ingested_ts': now - 3600,
            'persona_tags': ['soc_analyst', 'threat_hunter'],
            'factors': ['network_beacon'],
            'status': 'new',
            '_pipeline_done': False,
        },
    ]


def test_persona_forward_exec_creates_gate(monkeypatch):
    monkeypatch.setenv('FAST_TEST_MODE', '1')
    client = TestClient(app)
    rows = _sample_rows()

    monkeypatch.setattr(
        'src.api.report_forwarding_endpoints.decision_api.create_decision',
        lambda payload, actor=None: {'gate_id': 'gate-123'},
    )

    resp = client.post(
        '/api/v1/forwarding/persona',
        json={'rows': rows, 'persona': 'executive', 'top_n': 1, 'auto_create_gate': True},
    )
    assert resp.status_code == 200
    data = resp.json()
    result = data['results'][0]
    assert result['decision_gate']['gate_id'] == 'gate-123'
    assert result['explainability'] == 'minimal'


def test_backlog_report_aggregates_not_investigated(monkeypatch):
    monkeypatch.setenv('FAST_TEST_MODE', '1')
    client = TestClient(app)
    rows = _sample_rows()
    rows.append(
        {
            'event_id': 'evt-low',
            'triage_score': 0.2,
            'confidence': 0.4,
            'ingested_ts': time.time() - 7200,
            'persona_tags': ['soc_analyst'],
            'status': 'queued',
            '_pipeline_done': False,
            'factors': ['dns_exfiltration'],
        }
    )
    resp = client.post('/api/v1/forwarding/backlog', json={'rows': rows})
    assert resp.status_code == 200
    data = resp.json()
    assert data['not_investigated'] >= 2
    assert data['triage_buckets']['0.75+'] >= 1
    assert data['top_factors']
    assert data['prioritization']
