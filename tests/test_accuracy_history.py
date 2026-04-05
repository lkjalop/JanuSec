from core.finops.finops_manager import get_finops_manager


def test_accuracy_history_records():
    fm = get_finops_manager()
    fm.record_estimate('sessX', 10.0, 11.0)
    fm.record_estimate('sessY', 20.0, 19.0)
    hist = fm.accuracy_history()
    ids = [h['session_id'] for h in hist['history']]
    assert 'sessX' in ids and 'sessY' in ids
