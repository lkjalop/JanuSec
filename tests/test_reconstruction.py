import os
import json
import time

from src.graph.reconstruction import (
    normalize_event,
    score_path,
    adaptive_ewma_alpha,
    persist_session,
    load_session,
)


def test_normalize_and_score(tmp_path):
    e1 = {'user': 'Alice', 'host': 'HOST1', 'file_hash': 'ABCDEF', 'ts': 1670000000}
    e2 = {'user': 'alice', 'domain': 'Example.COM', 'nxdomain_rate': 0.5}
    n1 = normalize_event(e1)
    n2 = normalize_event(e2)
    path = [n1, n2]
    res = score_path(path)
    assert 'score' in res
    assert res['score'] >= 0


def test_adaptive_alpha():
    counts = [0, 10, 12, 9, 11]
    a = adaptive_ewma_alpha(counts, base_alpha=0.6)
    assert 0.3 <= a <= 0.85


def test_persist_and_load(tmp_path):
    sid = 'sess-123'
    payload = {'foo': 'bar'}
    # set SESSION_PERSIST_DIR to tmp
    os.environ['SESSION_PERSIST_DIR'] = str(tmp_path)
    persist_session(sid, payload)
    loaded = load_session(sid)
    assert loaded is not None
    assert loaded.get('foo') == 'bar'
