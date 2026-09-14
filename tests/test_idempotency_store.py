import os
import tempfile
from src.core.idempotency import IdempotencyStore


def test_idempotency_mark_and_query(tmp_path):
    db = tmp_path / 'idemp.db'
    s = IdempotencyStore(str(db))

    key = 'dlq/20260104-abc123.json'
    fp = 'deadbeef'

    assert not s.is_processed(key=key)
    assert not s.is_processed(fingerprint=fp)

    ok = s.mark_processed(key, fp, meta={'x':1})
    assert ok is True

    assert s.is_processed(key=key)
    assert s.is_processed(fingerprint=fp)

    # second mark returns False (already processed)
    ok2 = s.mark_processed(key, fp)
    assert ok2 is False

    s.record_replay(key, fp, actor='test', outcome='success', extra={'note':'ok'})
