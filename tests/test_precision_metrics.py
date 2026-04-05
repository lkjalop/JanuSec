import os
import tempfile
from datetime import date, datetime
from src.repositories.precision_metrics_repo import PrecisionMetricsRepo


def test_insert_and_get_daily_metrics(tmp_path):
    db_path = tmp_path / 'test.db'
    # Create schema
    from pathlib import Path
    sql = Path('db/migrations/010_precision_metrics.sql').read_text()
    import sqlite3
    conn = sqlite3.connect(str(db_path))
    conn.executescript(sql)
    conn.commit()
    conn.close()

    repo = PrecisionMetricsRepo(str(db_path))
    day = date(2025, 1, 1)
    repo.insert_daily_metrics(day, 'tenant-a', tp=10, fp=2, fn=1)
    rows = repo.get_daily_metrics('tenant-a', day, day)
    assert len(rows) == 1
    r = rows[0]
    assert r['tp'] == 10
    assert r['fp'] == 2
    assert abs(r['precision'] - (10/(10+2))) < 1e-6
