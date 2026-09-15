import json
import os
import time

import pytest

from fastapi.testclient import TestClient

from src.api.app import app as _app  # type: ignore


@pytest.mark.integration
def test_log_batch_cluster_flow():
    client = TestClient(_app)
    # Inject a simple mock rules engine into runtime to return deterministic rule hits
    from src.api import runtime_state as _rts

    class _MockHit:
        def __init__(self, rule):
            self.rule = rule

    class _MockRE:
        def evaluate_event(self, event):
            # return a single hit based on domain/ip present
            return [_MockHit('rule:network:ioc')]

        def score_and_classify(self, hits):
            return {'verdict': 'SUSPICIOUS', 'score': 0.8}

    _rts.rules_engine = _MockRE()
    # Build two synthetic events that share rules/factors/iocs
    ev1 = {
        'id': 'evt-int-1',
        'host': 'host-int',
        'details': {'ip': '10.0.0.1', 'domain': 'example.com'},
    }
    ev2 = {
        'id': 'evt-int-2',
        'host': 'host-int',
        'details': {'ip': '10.0.0.1', 'domain': 'example.com'},
    }
    # Require 'details.ip' and 'host' for enrichment completeness check
    import os
    os.environ['ENRICH_REQUIRED_FIELDS'] = 'details.ip,host'
    payload = {'events': [ev1, ev2], 'classify': False, 'include_rules': True, 'send_alerts': False}
    r = client.post('/api/v1/endpoints/log_batch', json=payload)
    assert r.status_code == 200
    body = r.json()
    assert body['accepted'] == 2
    events = body['events']
    assert len(events) == 2
    # second event should include clusters metadata and cluster_duplicate factor in rules when duplicate
    ev_meta1 = events[0]
    ev_meta2 = events[1]
    # Both should have processed cluster info
    assert 'clusters' in ev_meta1
    assert 'clusters' in ev_meta2
    cluster_id = ev_meta1['clusters'][0]['cluster_id']
    # second event should have duplicate factor (prefix)
    # Verify exact duplicate factor name present
    dup_factors = [str(f) for f in ev_meta2.get('rules', []) if str(f).startswith('cluster_duplicate:')]
    assert len(dup_factors) >= 1
    dup_name = dup_factors[0]
    assert dup_name.count(':') == 1 and dup_name.split(':')[0] == 'cluster_duplicate'

    # Fetch cluster details
    cr = client.get(f'/api/v1/clusters/{cluster_id}')
    assert cr.status_code == 200
    jd = cr.json()
    cluster = jd.get('cluster')
    assert cluster and cluster['cluster_id'] == cluster_id
    # Explainability: raw_signature and contributors should be present
    assert 'raw_signature' in cluster
    assert 'contributors' in cluster and isinstance(cluster['contributors'], dict)
    # Enrichment: since we required details.ip and host, and events include ip and host, completeness should be 1.0
    assert 'enrichment' in ev_meta1 and ev_meta1['enrichment']['completeness'] == 1.0
    assert 'required_weight' in ev_meta1['enrichment'] and 'present_weight' in ev_meta1['enrichment']
    # For robustness also check second event enrichment
    assert 'enrichment' in ev_meta2 and ev_meta2['enrichment']['completeness'] == 1.0
    assert 'required_weight' in ev_meta2['enrichment'] and 'present_weight' in ev_meta2['enrichment']
