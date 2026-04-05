import os

from fastapi.testclient import TestClient
from prometheus_client import generate_latest

from src.api.server import app

client = TestClient(app)

os.environ['ALERTS_API_KEYS'] = 'testkey'

MULTI_EVENT = {
    'events':[{
        'id':'multi1','host':'mh','proc_name':'powershell.exe','parent_proc':'winword.exe','dest_ip':'8.8.8.8','dest_port':4444
    }],
    'classify': True,
    'send_alerts': False,
    'include_rules': True
}

def test_rule_hit_counter():
    client.post('/api/v1/endpoints/log_batch', json=MULTI_EVENT)
    from src.api.metrics_init import REGISTRY
    metrics = generate_latest(REGISTRY).decode()
    assert 'rule_hits_total' in metrics
    assert 'lolbin_misuse' in metrics
    assert 'suspicious_outbound_port' in metrics
