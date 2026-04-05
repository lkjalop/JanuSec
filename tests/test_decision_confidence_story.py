import time
import json
import os
from fastapi.testclient import TestClient

import src.api.app as appmod

def test_decision_confidence_story_basic():
    os.environ.setdefault('PLATFORM_LITE_INIT','1')
    client = TestClient(appmod.app)
    # Seed decision with factors across domains
    factors = [
        'email:domain_homograph',
        'identity:credential_stuffing',
        'remote:jump_host_chain',
        'endpoint:unsigned_exec',
        'net:flow_microcluster_exfil',
        'cloud:public_bucket',
        'data:large_extract',
        'app:api_abuse',
        'corr_multi_domain_chain'
    ]
    dec = {
        'event_id': 'decision-conf-story-1',
        'factors': factors,
        'confidence': 0.85,
        'verdict': 'SUSPICIOUS',
        'ts': time.time(),
    }
    from src.api import runtime_state
    runtime_state.cache_set(dec['event_id'], dec)

    r = client.get(f"/api/v1/decisions/{dec['event_id']}/confidence_story")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body['event_id'] == dec['event_id']
    assert abs(body['final_confidence'] - dec['confidence']) < 1e-6
    narrative = body['narrative']
    assert narrative, 'Narrative should not be empty'
    # Ensure monotonic running confidence
    prev = -1.0
    for step in narrative:
        rc = step['running_confidence']
        assert rc >= prev, 'Confidence should be non-decreasing'
        prev = rc
    # Ensure domains represented includes at least 5 distinct ones
    assert len(set(body['domains_contributing'])) >= 5
