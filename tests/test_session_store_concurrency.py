import threading
import time
import random
import os
import tempfile
import shutil
import pytest
from src.api.session_store import JsonSessionStore, SqliteSessionStore

def _write_many(store, prefix, n, delay=0.001):
    for i in range(n):
        sid = f"{prefix}-{i}"
        store.save(sid, {'val': i, 'ts': time.time()})
        if delay:
            time.sleep(delay * random.random())

def _read_many(store, prefix, n):
    found = 0
    for i in range(n):
        sid = f"{prefix}-{i}"
        if store.load(sid):
            found += 1
    return found

@pytest.mark.parametrize("store_cls", [JsonSessionStore, SqliteSessionStore])
def test_session_store_concurrent_write_read(store_cls):
    tmpdir = tempfile.mkdtemp()
    try:
        if store_cls is SqliteSessionStore:
            store = store_cls(os.path.join(tmpdir, "sessions.db"))
        else:
            store = store_cls(tmpdir)
        n = 30
        threads = []
        for t in range(4):
            th = threading.Thread(target=_write_many, args=(store, f"sid{t}", n))
            threads.append(th)
            th.start()
        for th in threads:
            th.join()
        # Read back
        total = 0
        for t in range(4):
            total += _read_many(store, f"sid{t}", n)
        assert total == 4 * n
    finally:
        shutil.rmtree(tmpdir)
