import os
import json
import time
from src.api.retrain_consumer import consume_retrain_tasks, _ensure_training_dir


def test_retrain_writer_atomic(tmp_path):
    # Create a fake outbox by monkeypatching the repository functions
    from src.repositories import outbox_repo_sqlite as outbox_repo

    # Prepare fake rows
    rows = [
        {'id': 1, 'payload_json': json.dumps({'a': 1})},
        {'id': 2, 'payload_json': json.dumps({'b': 2})},
    ]

    orig_next = outbox_repo.next_pending
    orig_mark = outbox_repo.mark_done

    try:
        outbox_repo.next_pending = lambda limit=100: rows
        processed = []
        def mark_done(rid):
            processed.append(rid)
        outbox_repo.mark_done = mark_done

        out = consume_retrain_tasks(limit=10)
        # should return processed ids
        assert set(out) == {1,2}
        td = _ensure_training_dir()
        files = [f for f in os.listdir(td) if f.startswith('retrain_') and f.endswith('.ndjson')]
        assert files, 'No retrain files written'
        # read last file
        fpath = os.path.join(td, sorted(files)[-1])
        with open(fpath, 'r', encoding='utf-8') as fh:
            lines = [l.strip() for l in fh.readlines() if l.strip()]
        assert len(lines) >= 2
    finally:
        outbox_repo.next_pending = orig_next
        outbox_repo.mark_done = orig_mark
