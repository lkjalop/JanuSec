import os
import tempfile
from datetime import datetime, timedelta
from src.repositories.precision_metrics_repo import get_db_path, record_rule_result, get_rule_precision, get_daily_trend


def test_precision_repo_roundtrip(tmp_path):
    dbfile = tmp_path / "pm.db"
    os.environ['PRECISION_METRICS_DB'] = str(dbfile)

    # record 3 positives and 2 negatives for rule 'r1'
    now = datetime.utcnow()
    record_rule_result('r1', True, when=now - timedelta(days=1))
    record_rule_result('r1', True, when=now)
    record_rule_result('r1', True, when=now)
    record_rule_result('r1', False, when=now)
    record_rule_result('r1', False, when=now - timedelta(days=2))

    rp = get_rule_precision('r1', days=7)
    assert rp['rule_id'] == 'r1'
    assert rp['total'] >= 5
    assert 'precision' in rp

    trend = get_daily_trend(days=7)
    assert isinstance(trend, list)
