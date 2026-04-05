import os
from types import SimpleNamespace

from src.correlation.dispatcher import correlate
from src.feedback.store import GLOBAL_FEEDBACK_STORE


def seed_quality(factor: str, tp: int, fp: int):
    fac_obj = [{'name': factor}]
    for i in range(tp):
        GLOBAL_FEEDBACK_STORE.upsert(f'e-tp-{factor}-{i}', 'tp', fac_obj, {'confidence':0.9,'verdict':'MALICIOUS'})
    for i in range(fp):
        GLOBAL_FEEDBACK_STORE.upsert(f'e-fp-{factor}-{i}', 'fp', fac_obj, {'confidence':0.05,'verdict':'BENIGN'})
    GLOBAL_FEEDBACK_STORE.recompute_quality()


def test_correlate_dynamic_scaling_monkeypatch(monkeypatch):
    os.environ['FEATURE_DYNAMIC_FACTOR_SCALING'] = '1'
    # Seed two factors of differing quality (both decent to push scaling > baseline)
    seed_quality('dyn:highA', tp=6, fp=1)
    seed_quality('dyn:highB', tp=5, fp=1)

    # Monkeypatch correlation sub-modules so only temporal returns controlled output
    base_delta = 0.2
    def fake_temporal(event, factors):
        return ['dyn:highA','dyn:highB'], base_delta
    def noop(*_a, **_k):
        return [], 0.0
    monkeypatch.setattr('src.correlation.dispatcher.record_temporal_correlation', fake_temporal)
    monkeypatch.setattr('src.correlation.dispatcher.record_cooccurrence_correlation', noop)
    monkeypatch.setattr('src.correlation.dispatcher.record_campaign_correlation', noop)
    monkeypatch.setattr('src.correlation.dispatcher.record_suppression_correlation', noop)
    monkeypatch.setattr('src.correlation.dispatcher.record_sequence_correlation', noop)

    new_factors, scaled_delta = correlate({'event_id':'E1'}, [])
    assert set(new_factors) == {'dyn:highA','dyn:highB'}
    # Compute expected scale
    _,_,q1 = GLOBAL_FEEDBACK_STORE.get_factor_quality('dyn:highA')
    _,_,q2 = GLOBAL_FEEDBACK_STORE.get_factor_quality('dyn:highB')
    avg_q = (q1 + q2)/2.0
    expected_scale = 0.85 + 0.3 * avg_q
    expected_scale = max(0.7, min(1.25, expected_scale))
    # Allow small floating diff
    assert abs(scaled_delta - base_delta * expected_scale) < 1e-6, f"Scaled delta mismatch: {scaled_delta} vs {base_delta*expected_scale}" 
