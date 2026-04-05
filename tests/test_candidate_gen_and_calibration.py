from src.ml.candidate_gen import grid_over_factors
from src.ml.calibration_runner import grid_search


def test_grid_over_factors_small():
    cands = grid_over_factors(['a','b'], base=0.0, step=0.5, levels=2)
    assert isinstance(cands, list)
    assert len(cands) == 4
    assert all(isinstance(c, dict) for c in cands)


def test_grid_search_multi_factor():
    # labels: one positive with factors ['a','b'], one negative with ['b']
    labels = [
        {'decision_id': '1', 'label': 'true_positive', 'factors': ['a','b']},
        {'decision_id': '2', 'label': 'false_positive', 'factors': ['b']}
    ]
    candidates = [
        {'weights': {'a':0.6,'b':0.1}, 'threshold': 0.5},
        {'weights': {'a':0.2,'b':0.6}, 'threshold': 0.5}
    ]
    res = grid_search(candidates, labels)
    assert 'winner_index' in res
    assert isinstance(res['results'], list)
    assert res['winner_index'] in (0,1)
