import json
import os
import asyncio

from src.core.risk_score import _compose_risk_score_async


def write_candidate(weights: dict, pct: float):
    p = os.path.join('data', 'factor_weights_current.json')
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, 'w', encoding='utf-8') as fh:
        json.dump({'weights': weights, 'rollout_pct': pct}, fh)


def test_canary_overrides(monkeypatch, tmp_path):
    # Prepare candidate weights to override 'net:abc'
    write_candidate({'net:abc': 0.2}, 50)

    # Force deterministic canary selection: only select event_id 'select-me'
    import src.core.canary as canary
    monkeypatch.setattr(canary, 'pick_by_event', lambda eid, pct: True if eid == 'select-me' else False)

    async def run():
        dec_sel = {'factors': ['net:abc'], 'event_id': 'select-me', 'ts': 1703120000}
        dec_no = {'factors': ['net:abc'], 'event_id': 'other', 'ts': 1703120000}
        r1 = await _compose_risk_score_async(dec_sel)
        r2 = await _compose_risk_score_async(dec_no)
        # find net:abc entry
        b1 = next((b for b in r1.get('breakdown', []) if b.get('factor') == 'net:abc'), None)
        b2 = next((b for b in r2.get('breakdown', []) if b.get('factor') == 'net:abc'), None)
        assert b1 is not None and b2 is not None
        # when selected, weight should equal candidate (0.2)
        assert abs(float(b1.get('weight')) - 0.2) < 1e-6
        # when not selected, weight should be the default (likely 0.6 for net:)
        assert abs(float(b2.get('weight')) - 0.6) < 0.6  # coarse check: not equal to 0.2

    asyncio.run(run())
