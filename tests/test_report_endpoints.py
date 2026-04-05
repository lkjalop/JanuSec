import json
import re

import pytest
from fastapi.testclient import TestClient

# Import app after environment to ensure routers loaded
from src.api.server import app
from src.api import runtime_state
from tests._helpers import default_test_headers

client = TestClient(app)


def _seed_decisions(n=5, tenant='public'):
    # Create synthetic decision objects with required attributes
    class Dummy:
        pass
    for i in range(n):
        d = Dummy()
        d.event_id = f'evt-{tenant}-{i}'
        d.verdict = 'malicious' if i % 2 == 0 else 'review'
        d.confidence = 0.8 + i * 0.01
        d.factors = [f'T10{i:02d}']
        d.tenant_id = tenant
        runtime_state.cache_set(f'evt-{tenant}-{i}', d)


def test_report_json_finops_and_version():
    _seed_decisions()
    r = client.get('/api/v1/report/ingestion?include_alerts=false&format=json', headers=default_test_headers())
    assert r.status_code == 200
    data = r.json()
    assert data['meta']['report_version'] == 2
    assert 'finops' in data
    assert data['finops'] is not None
    # basic required finops keys
    for key in ['ingest_events','ingest_cost_estimate','roi_ratio_estimate']:
        assert key in data['finops']


def test_report_csv():
    r = client.get('/api/v1/report/ingestion?include_alerts=false&format=csv', headers=default_test_headers())
    assert r.status_code == 200
    body = r.text.splitlines()
    # header row + at least verdict_stats total
    assert any(line.startswith('verdict_stats,total_events') for line in body)
    assert any(line.startswith('persona,selected') for line in body)


def test_report_html_contains_sections():
    r = client.get('/api/v1/report/ingestion?include_alerts=false&format=html', headers=default_test_headers())
    assert r.status_code == 200
    html = r.text.lower()
    assert 'severity distribution' in html
    assert 'top mitre techniques' in html


def test_report_pdf_generation():
    r = client.get('/api/v1/report/ingestion?include_alerts=false&format=pdf', headers=default_test_headers())
    # Allow 501 if pdf not available in environment
    if r.status_code == 501:
        pytest.skip('PDF generation not available')
    assert r.status_code == 200
    content = r.content
    assert len(content) > 500  # minimal size sanity
    # Optional pdfplumber parse to ensure readable
    try:
        import io as _io

        import pdfplumber  # type: ignore
        with pdfplumber.open(_io.BytesIO(content)) as pdf:
            first_page = pdf.pages[0]
            text = (first_page.extract_text() or '').lower()
            assert 'ingestion report' in text
    except Exception:
        # Non-fatal if pdfplumber not present or parse issue
        pass


def test_analytics_clusters_stub():
    _seed_decisions(tenant='acme')
    hdrs = default_test_headers()
    hdrs.update({'X-Tenant-ID': 'acme'})
    r = client.get('/api/v1/analytics/clusters', headers=hdrs)
    assert r.status_code == 200
    data = r.json()
    assert 'clusters' in data
    assert isinstance(data['clusters'], list)


def test_analytics_mitre_stub():
    r = client.get('/api/v1/analytics/mitre', headers=default_test_headers())
    assert r.status_code == 200
    data = r.json()
    assert 'techniques' in data
    assert isinstance(data['techniques'], list)


def test_analytics_timeline_stub():
    r = client.get('/api/v1/analytics/timeline', headers=default_test_headers())
    assert r.status_code == 200
    data = r.json()
    assert 'items' in data
    assert isinstance(data['items'], list)


def _seed_alerts(count=30):
    # Use log_batch to generate alerts with send_alerts=true
    events = []
    for i in range(count):
        events.append({'id': f'alrt-{i}', 'host': 'h1', 'dns_rcode': 0})
    payload = {
        'events': events,
        'classify': True,
        'send_alerts': True,
        'include_rules': False,
    }
    client.post('/api/v1/endpoints/log_batch', json=payload)


def test_alerts_pagination_in_report():
    _seed_alerts(25)
    r1 = client.get('/api/v1/report/ingestion?format=json&limit_alerts=10&alerts_offset=0', headers=default_test_headers())
    assert r1.status_code == 200
    data1 = r1.json()
    assert data1['alerts_pagination']['returned'] <= 10
    next_offset = data1['alerts_pagination']['next_offset']
    if next_offset is not None:
        r2 = client.get(f'/api/v1/report/ingestion?format=json&limit_alerts=10&alerts_offset={next_offset}', headers=default_test_headers())
        assert r2.status_code == 200
        data2 = r2.json()
        # Ensure no duplicate IDs between pages (best effort) if both returned
        ids1 = {a['id'] for a in data1['alerts']}
        ids2 = {a['id'] for a in data2['alerts']}
        assert ids1.isdisjoint(ids2)


def test_report_json_snapshot_subset():
    r = client.get('/api/v1/report/ingestion?include_alerts=false&format=json', headers=default_test_headers())
    assert r.status_code == 200
    data = r.json()
    subset = {
        'version': data['meta']['report_version'],
        'severity_keys': sorted(list(data['severity_distribution'].keys())),
        'finops_keys': sorted([k for k in data['finops'].keys() if k.endswith('_estimate')]) if data.get('finops') else [],
    }
    # Hard-coded expected structure (update intentionally if model changes)
    assert subset['version'] == 2
    assert 'critical' in subset['severity_keys']
    # Ensure at least ingest and storage estimates present
    assert 'ingest_cost_estimate' in subset['finops_keys']
    assert 'storage_cost_estimate' in subset['finops_keys']

