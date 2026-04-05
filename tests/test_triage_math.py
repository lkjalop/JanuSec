from src.analysis.triage import compute_triage_score


def test_triage_computation_basic():
    inputs = {'dread': 8.0, 'correlation': 0.6, 'density': 0.4, 'confidence': 0.8, 'rarity': 0.2}
    out = compute_triage_score(inputs)
    assert 'triage_score' in out
    assert 0.0 <= out['triage_score'] <= 1.0
    bd = out['breakdown']
    assert bd['dread'] > 0
    assert bd['correlation'] == 0.6


def test_weights_normalization_env(monkeypatch):
    monkeypatch.setenv('TRIAGE_WEIGHTS_JSON', '{"dread":3,"correlation":1}')
    out = compute_triage_score({'dread':5,'correlation':0.5,'density':0.1,'confidence':0.2,'rarity':0.0})
    assert 'weights' in out
    w = out['weights']
    # weights should sum to ~1
    assert abs(sum(w.values()) - 1.0) < 1e-6
