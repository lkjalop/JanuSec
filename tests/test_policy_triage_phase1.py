import json
import time

from fastapi.testclient import TestClient

from src.api.server import app
from tests._helpers import default_test_headers


def make_decision_in_cache(client: TestClient, event_id: str, tenant_id: str | None = None):
    # Insert a simple decision into DECISION_CACHE via the demo crowdstrike endpoint
    # or by directly posting a simple record into the in-memory cache via runtime helper.
    # Prefer using the public upload path to avoid touching internals in tests.
    payload = {
        'event_id': event_id,
        'verdict': 'GOOD',
        'confidence': 0.1,
        'factors': ['test:initial']
    }
    # Use the internal helper endpoint in server module if available (crowdstrike_sync uses cache_set)
    # Otherwise, we'll emulate by calling the CSV upload path which updates DECISION_CACHE lightly.
    return payload


def test_policy_triage_explain_and_risk_override():
    client = TestClient(app)

    # Prepare a decision in the cache (direct manipulation via runtime_state helper)
    from src.api.runtime_state import DECISION_CACHE
    event_id = f'test-event-{int(time.time()*1000)}'
    entry = {
        'event_id': event_id,
        'verdict': 'GOOD',
        'confidence': 0.12,
        'factors': ['unit:test'],
        # include precomputed risk fields so /api/v1/decisions/{id}/risk can return without
        # invoking compose_risk_score (avoids heavy deps in unit test environment)
        'risk_score': 0.12,
        'risk_breakdown': [{'factor': 'unit:test', 'contribution': 0.12}],
    }
    # Write directly into DECISION_CACHE as a plain dict so the risk explain
    # early-return branch (checks for keys with `in`) works in tests.
    DECISION_CACHE[event_id] = entry

    # Confirm baseline explain does NOT include policy_forced
    r = client.get(f'/api/v1/decisions/{event_id}/explain', headers=default_test_headers())
    assert r.status_code == 200
    baseline = r.json()
    assert baseline.get('verdict') in ('GOOD', 'UNKNOWN') or 'verdict' in baseline
    assert baseline.get('policy_forced') is None

    # Enable the CSV policy for an api key by calling the CSV policy endpoint
    api_key = 'testkey-phase1'
    # Authenticate the caller using the default test headers, but set the
    # target API key in the x-api-key header so the policy is applied for
    # the intended key.
    hdrs = default_test_headers()
    hdrs.update({'x-api-key': api_key})
    payload = {'never_auto_clear': True}
    r2 = client.post('/api/v1/csv/policy', headers=hdrs, json=payload)
    assert r2.status_code == 200
    assert r2.json().get('never_auto_clear') is True

    # Now call explain with that api key; expect final_decision='review' and policy_forced=True
    r3 = client.get(f'/api/v1/decisions/{event_id}/explain', headers=hdrs)
    assert r3.status_code == 200
    j = r3.json()
    assert j.get('final_decision') == 'review'
    assert j.get('policy_forced') is True

    # Call the risk explain endpoint; expect the override as well
    r4 = client.get(f'/api/v1/decisions/{event_id}/risk', headers=hdrs)
    assert r4.status_code == 200
    jr = r4.json()
    # risk endpoint returns event_id and risk fields; ensure override present
    assert jr.get('final_decision') == 'review'
    assert jr.get('policy_forced') is True

    # Ensure DECISION_CACHE entry unchanged (policy only affects explain payloads)
    from src.api.runtime_state import cache_get as _cache_get
    stored = _cache_get(event_id)
    # Stored verdict remains original 'GOOD' (case-insensitive check)
    if isinstance(stored, dict):
        v = stored.get('verdict')
    else:
        v = getattr(stored, 'verdict', None)
    assert v is not None
    assert str(v).upper() != 'REVIEW'
