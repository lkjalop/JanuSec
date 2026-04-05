import time
import uuid
from src.api import dispatch_outbox as outbox


def test_enqueue_and_get_by_id(tmp_path, monkeypatch):
    # ensure DB path is inside tmp_path
    monkeypatch.setenv('PWD', str(tmp_path))
    # Use a unique id
    did = 'd-' + uuid.uuid4().hex
    outbox.enqueue(did, 't1', '/api/v1/graph/identity/ingest', {'payload': {'user': 'alice'}})
    r = outbox.get_by_id(did)
    assert r is not None
    assert r['tenant_id'] == 't1'


def test_compute_backoff_monotonic():
    b1 = outbox.compute_backoff(1, base=1.0, cap=60.0, jitter=0.1)
    b2 = outbox.compute_backoff(2, base=1.0, cap=60.0, jitter=0.1)
    b3 = outbox.compute_backoff(3, base=1.0, cap=60.0, jitter=0.1)
    assert b1 > 0
    assert b2 >= b1
    assert b3 >= b2


def test_mark_attempt_and_repair(tmp_path, monkeypatch):
    monkeypatch.setenv('PWD', str(tmp_path))
    did = 'd-' + uuid.uuid4().hex
    outbox.enqueue(did, 't2', '/api/v1/graph/dns/lookup', {'payload': {'q': 'example.com'}})
    # mark an attempt (failure)
    outbox.mark_attempt(did, attempts=1, last_error='net_err', status='pending')
    r = outbox.get_by_id(did)
    assert r['attempts'] == 1
    assert r['last_error'] == 'net_err'
    # repair should reset attempts and status
    outbox.repair(did)
    r2 = outbox.get_by_id(did)
    assert r2['attempts'] == 0
    assert r2['status'] == 'pending'
