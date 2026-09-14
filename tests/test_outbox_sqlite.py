import os
import time
import json


def test_outbox_sqlite_basic(tmp_path, monkeypatch):
    dbp = tmp_path / 'outbox.db'
    monkeypatch.setenv('OUTBOX_SQLITE_PATH', str(dbp))
    from src.repositories import outbox_repo_sqlite as repo

    # enqueue two items with same logical key -> upsert behavior
    id1 = repo.enqueue('slack', 't1', 'e1', {'x': 1})
    assert id1 > 0
    id2 = repo.enqueue('slack', 't1', 'e1', {'x': 2})
    # second call should not create duplicate key entry
    assert id2 >= 0

    # next_pending claims item
    rows = repo.next_pending(limit=5, max_attempts=3)
    assert len(rows) >= 1
    row = rows[0]
    assert row['connector'] == 'slack'
    payload = row.get('payload_json')
    if isinstance(payload, str):
        json.loads(payload)

    # mark_done by row id removes it
    repo.mark_done(int(row['id']))
    rows2 = repo.next_pending(limit=5, max_attempts=3)
    # No items as queue empty
    assert len(rows2) == 0

    # enqueue new and test mark_done_by_key
    repo.enqueue('slack', 't1', 'e2', {'a': 1})
    repo.mark_done_by_key('slack', 't1', 'e2')
    rows3 = repo.next_pending(limit=5, max_attempts=3)
    assert len(rows3) == 0

    # test fail sets next_retry in future and preserves row
    rid = repo.enqueue('slack', 't1', 'e3', {'a': 3})
    rows4 = repo.next_pending(limit=5, max_attempts=3)
    assert rows4
    r4 = rows4[0]
    repo.fail(int(r4['id']), 'err', retry_in=0.5)
    # Immediately should not return due to next_retry future
    assert repo.next_pending(limit=5, max_attempts=3) == []
    time.sleep(0.6)
    # Now should be available
    assert repo.next_pending(limit=5, max_attempts=3)
