from src.core.scoring.confidence import normalize_score, combine_scores


def test_normalize_score_bounds():
    assert normalize_score(-5) == 0.0
    assert normalize_score(0.0) == 0.0
    assert normalize_score(0.5) == 0.5
    assert normalize_score(2.0) == 1.0


def test_combine_scores_methods():
    scores = [0.2, 0.8]
    assert combine_scores(scores, 'max') == 0.8
    assert abs(combine_scores(scores, 'mean') - 0.5) < 1e-9
    prod_val = combine_scores(scores, 'prod')
    assert abs(prod_val - 0.84) < 1e-9  # 1 - (1-0.2)*(1-0.8) = 0.84


def test_combine_scores_empty():
    assert combine_scores([], 'max') == 0.0
    assert combine_scores([], 'mean') == 0.0
    assert combine_scores([], 'prod') == 0.0
