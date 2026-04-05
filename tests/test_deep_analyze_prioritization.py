from src.api.deep_analyze_endpoints import prioritize_rows_for_llm


def _row(verdict: str, score: float, factors=None):
    factors = factors or []
    return {'verdict': verdict, '_dread': {'score': score}, 'factors': factors}


def test_prioritize_rows_orders_by_dread_desc():
    rows = [
        _row('HIGH', 4.0),
        _row('SUSPICIOUS', 8.0),
        _row('CRITICAL', 6.0),
        _row('LOW', 9.0),  # should be ignored
    ]
    pending = prioritize_rows_for_llm(rows, processed_indexes=set(), queued_indexes=set(), limit=2)
    assert [idx for idx, _ in pending] == [1, 2]


def test_prioritize_rows_skips_processed_or_queued_and_honors_limit_zero():
    rows = [
        _row('SUSPICIOUS', 3.0),
        _row('SUSPICIOUS', 2.0),
        _row('SUSPICIOUS', 1.0),
    ]
    processed = {0}
    queued = {1}
    pending = prioritize_rows_for_llm(rows, processed, queued, limit=0)
    assert [idx for idx, _ in pending] == [2]
