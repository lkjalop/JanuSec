import os
import time

from src.core.idempotency import IdempotencyStore, run_idempotent, compute_idempotency_id


def test_idempotency_exactly_once(tmp_path):
    db = tmp_path / 'idem.sqlite'
    store = IdempotencyStore(str(db))
    calls = {'n': 0}

    def action():
        calls['n'] += 1
        return {'ok': True, 'ts': time.time()}

    key = 'k1'
    res1 = run_idempotent(store, key, action)
    res2 = run_idempotent(store, key, action)
    assert res1['ok'] and res2['ok']
    assert calls['n'] == 1  # executed once


def test_idempotency_key_compute():
    k = compute_idempotency_id('org','pb','1.0.0','alert1','step-A','phash','2025-10-04T01')
    assert isinstance(k, str) and len(k) == 64


def test_alert_dedup_window(monkeypatch):
    # Import after setting env to disable persisted history
    os.environ['ALERTS_PERSIST_HISTORY'] = '0'
    from src.api.alerts_endpoints import append_alert, ALERT_RING, ALERT_RING_LOCK
    # Clear ring
    with ALERT_RING_LOCK:
        ALERT_RING.clear()
    base = {
        'rule_id': 'r1',
        'entity_id': 'host-1',
        'iocs': ['iocA','iocB'],
        'ts': time.time(),
        'verdict': 'SUSPICIOUS',
        'score': 0.8,
    }
    a1 = base.copy(); a1['id'] = 'a1'
    a2 = base.copy(); a2['id'] = 'a2'
    append_alert(a1)
    append_alert(a2)
    with ALERT_RING_LOCK:
        assert len(ALERT_RING) == 2
        # The second alert should carry a dedup_increment marker
        assert ALERT_RING[1].get('dedup_increment') == 1
