import re, time
from fastapi.testclient import TestClient
from src.api.app import create_app
app = create_app({'mode': 'test'})
import os

# Ensure small cap for testing
os.environ['METRICS_MAX_TENANTS'] = '5'

# Create two tenants and ensure metrics include tenant label when under cap

def test_tenant_metric_label_appears_when_under_cap():
    client = TestClient(app)
    from src.api.runtime_state import get_server_runtime_state, get_file_batch_analysis
    runtime = get_server_runtime_state(app)
    fb = get_file_batch_analysis(runtime)
    fb.clear()
    fb['batch-T'] = {'files': [{'sha256': 'bbb1', 'factors': ['high_entropy']}]}
    # request as tenant A
    r1 = client.post('/api/v1/graph/session/build', json={'session_ids': ['batch-T'], 'correlate': True, 'ewma': False}, headers={'X-Tenant-ID': 'tenant-A'})
    assert r1.status_code == 200
    # request as tenant B
    r2 = client.post('/api/v1/graph/session/build', json={'session_ids': ['batch-T'], 'correlate': True, 'ewma': False}, headers={'X-Tenant-ID': 'tenant-B'})
    assert r2.status_code == 200
    # scrape metrics and verify tenant labels present for detector_factor_total
    m = client.get('/metrics')
    assert m.status_code == 200
    txt = m.text
    pattern = re.compile(r'detector_factor_total\{factor="high_entropy",tenant="tenant-A"\} 1')
    assert pattern.search(txt), f"tenant label not present in metrics scrape:\n{txt[:400]}"


def test_cardinality_guard_prevents_label_when_exceeded():
    client = TestClient(app)
    from src.api.runtime_state import get_server_runtime_state, get_file_batch_analysis
    runtime = get_server_runtime_state(app)
    fb = get_file_batch_analysis(runtime)
    fb.clear()
    fb['batch-T2'] = {'files': [{'sha256': 'ccc1', 'factors': ['high_entropy']}]}
    # create more tenants than METRICS_MAX_TENANTS
    for i in range(7):
        tid = f't{i}'
        r = client.post('/api/v1/graph/session/build', json={'session_ids': ['batch-T2'], 'correlate': True, 'ewma': False}, headers={'X-Tenant-ID': tid})
        assert r.status_code == 200
    # scrape metrics and verify tenant label not present for one of them (guard should have kicked in)
    m = client.get('/metrics')
    txt = m.text
    # When cardinality guard suppresses tenant labeling we emit tenant="" as a stable label value.
    unlabeled_pattern = re.compile(r'detector_factor_total\{factor="high_entropy",tenant=""\} \d+')
    assert unlabeled_pattern.search(txt), f"Expected suppressed-tenant metric (tenant=\"\") when cap exceeded but none found:\n{txt[:400]}"
