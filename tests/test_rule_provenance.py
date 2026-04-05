import time
from fastapi.testclient import TestClient

from src.api.server import app as _app
from src.api import runtime_state
from src.api.dependencies import get_platform_state

client = TestClient(_app)


def test_provenance_in_decision_cache():
    # Build an event that should trigger at least one correlation rule we added
    ev = {
        'id': 'prov-evt-1',
        'host': 'host-prov',
        'details': {'process': {'name': 'powershell.exe', 'parent': 'explorer.exe'}},
        # include factors expected by one of the batch_more rules
        'powershell_encoded': True,
        'amsi_disable_call': True,
    }
    # Post to ingest endpoint
    from tests._helpers import default_test_headers
    r = client.post('/api/v1/events', json=ev, headers=default_test_headers('10.10.10.2'))
    assert r.status_code == 200
    body = r.json()
    event_id = body.get('event_id')
    assert event_id

    # Drain event queue to deterministically process the event in tests
    try:
        from src.api.runtime_state import drain_event_queue_for_tests
        drain_event_queue_for_tests()
    except Exception:
        time.sleep(0.2)

    # Check DECISION_CACHE for the decision
    cache = getattr(runtime_state, 'DECISION_CACHE', None) or globals().get('DECISION_CACHE')
    dec = None
    if isinstance(cache, dict):
        dec = cache.get(event_id)
    # Fallback: check PlatformState internal decisions mapping (some tests wire state there)
    if dec is None:
        ps = get_platform_state()
        try:
            dec = ps._decisions.get(event_id)  # type: ignore[attr-defined]
        except Exception:
            dec = None
    assert dec is not None, 'Decision not found in DECISION_CACHE or PlatformState._decisions'

    # Normalize decision into a dict-like structure for assertions
    dec_dict = None
    try:
        if hasattr(dec, 'model_dump'):
            dec_dict = dec.model_dump()
        elif isinstance(dec, dict):
            dec_dict = dec
        else:
            # try attribute access fallback
            dec_dict = {k: getattr(dec, k) for k in ('event_id','verdict','confidence','factors') if hasattr(dec, k)}
    except Exception:
        dec_dict = None
    assert isinstance(dec_dict, dict)

    # Provenance fields
    corr = dec_dict.get('correlation_factors') or []
    assert isinstance(corr, list)
    # Accept either legacy string factors like 'corr:<rule>' in the factors list
    # or structured correlation_factors objects that include our metadata keys.
    has_legacy = any(isinstance(f, str) and f.startswith('corr:') for f in dec_dict.get('factors', []))
    has_structured = any(isinstance(c, dict) and ('factors_triggered' in c or 'tags' in c or 'sensor_domains' in c) for c in corr)
    assert has_legacy or has_structured, f'No correlation provenance found: factors={dec_dict.get("factors")}, corr={corr}'

    # graph_evidence may be present (best-effort) - if present it should be a dict
    if 'graph_evidence' in dec_dict:
        assert isinstance(dec_dict.get('graph_evidence'), dict)

    # risk_breakdown if present must be list or dict
    if 'risk_breakdown' in dec_dict:
        assert isinstance(dec_dict.get('risk_breakdown'), (list, dict))