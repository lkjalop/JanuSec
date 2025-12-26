from fastapi.testclient import TestClient
import os

from src.api.app import create_app
from src.live import asn_lookup
from src.live import asn_stats
from src.api import runtime_state


def test_asn_seeding_and_rare_factor(monkeypatch):
    app = create_app()
    client = TestClient(app)

    # seed deterministic ASN mapping for test IP
    asn_lookup.clear_mapping()
    asn_lookup.seed_mapping({'8.8.8.8': 'AS65001', '8.8.4.4': 'AS65002'})

    # ensure ASN stats are in a known state via runtime test helper
    runtime_state.reset_for_tests()

    # set rarirty threshold low so the seed ASNs can be considered rare if stats report low counts
    monkeypatch.setenv('ASN_RARITY_THRESHOLD','0.0')

    # Use synthetic batch ids that will be synthesized by the session builder
    payload = {
        "session_ids": ["batch-overlap-A","batch-overlap-B"],
        "correlate": True,
        "ewma": False,
    }

    r = client.post('/api/v1/graph/session/build', json=payload)
    assert r.status_code == 200
    j = r.json()

    # The asn_stats should record AS65001
    pct = asn_stats.percentile('AS65001')
    # percentile should be a number; rarity should be available
    rty = asn_stats.rarity('AS65001')
    assert isinstance(pct, float)
    assert isinstance(rty, float)

    # session summary should include asn_rare factor when threshold is low
    summary = j.get('summary') or {}
    factors = summary.get('factors') or []
    found = False
    for f in factors:
        if isinstance(f, dict):
            if f.get('factor') == 'asn_rare' and f.get('asn') in ('AS65001','AS65002'):
                found = True; break
    assert found
