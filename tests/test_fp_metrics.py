from src.core.correlation.rules.registry import record_false_positive, record_true_positive, get_rule_metrics


def test_fp_tp_hooks():
    # ensure metrics start empty
    m0 = get_rule_metrics()
    assert isinstance(m0, dict)
    # record some metrics
    record_false_positive('test_rule')
    record_false_positive('test_rule')
    record_true_positive('test_rule')
    metrics = get_rule_metrics()
    assert metrics.get('test_rule')['fp'] == 2
    assert metrics.get('test_rule')['tp'] == 1
