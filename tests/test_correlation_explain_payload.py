import json
import time
from fastapi.testclient import TestClient

from src.api.app import app as api_app


def make_decision_with_corr(event_id: str):
    # Build a decision object that resembles what _record_decision_async produces
    dec = {
        'event_id': event_id,
        'id': event_id,
        'verdict': 'SUSPICIOUS',
        'confidence': 0.75,
        'factors': ['network:scan','ip:rare'],
        'ts': time.time(),
        'correlation_factors': [
            {'name': 'internal_scan_pattern', 'mitre': ['T1595'], 'severity': 'high', 'confidence_boost': 0.4, 'window_seconds': 120},
            {'name': 'suspicious_user_agent', 'mitre': ['T1071'], 'severity': 'low', 'confidence_boost': 0.05, 'window_seconds': 3600}
        ]
    }
    return dec


def test_explain_includes_structured_correlation_factors(monkeypatch):
    client = TestClient(api_app)

    # Insert a decision into the DECISION_CACHE used by the API via the
    # canonical runtime_state API so tests work whether the cache is an
    # in-memory dict or an adapter-backed DecisionStore.
    from src.api import runtime_state
    event_id = 'test-evt-corr-1'
    dec = make_decision_with_corr(event_id)
    runtime_state.cache_set(event_id, dec)

    # Call explain endpoint
    r = client.get(f'/api/v1/decisions/{event_id}/explain')
    assert r.status_code == 200, r.text
    payload = r.json()

    # Correlation_factors should be present and be a list
    assert 'correlation_factors' in payload
    cfs = payload['correlation_factors']
    assert isinstance(cfs, list)
    assert len(cfs) == 2

    # Validate fields on each structured correlation factor
    for cf in cfs:
        assert 'name' in cf and isinstance(cf['name'], str) and cf['name']
        assert 'severity' in cf and cf['severity'] in {'low','medium','high'}
        assert 'confidence_boost' in cf and isinstance(cf['confidence_boost'], (float,int))
        assert 'mitre' in cf and isinstance(cf['mitre'], list)
        assert 'window_seconds' in cf and isinstance(cf['window_seconds'], int)
