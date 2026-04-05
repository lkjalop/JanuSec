from src.eval.ab_analysis import uplift_and_pvalue, beta_interval, sample_size_for_uplift


def test_uplift_and_pvalue_basic():
    # control: 50/100, treatment: 60/100 -> uplift 0.1
    res = uplift_and_pvalue(50, 100, 60, 100)
    assert abs(res['uplift'] - 0.1) < 1e-6
    assert 0.0 <= res['p_value'] <= 1.0


def test_beta_interval_edge():
    lo, hi = beta_interval(0, 0)
    assert lo == 0.0 and hi == 1.0
    lo2, hi2 = beta_interval(5, 10)
    assert 0.0 <= lo2 < hi2 <= 1.0


def test_sample_size():
    n = sample_size_for_uplift(0.1, 0.02)
    assert n > 0
