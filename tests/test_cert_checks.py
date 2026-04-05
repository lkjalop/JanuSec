import time
import os
from src.integrations import cert_checks as cc
from src.integrations import threat_intel_store as tis


def test_cert_check_queue_and_process(monkeypatch, tmp_path):
    # Use temp DB path to isolate
    dbp = str(tmp_path / 'ti.sqlite')
    monkeypatch.setenv('THREAT_INTEL_DB_PATH', dbp)
    # Ensure threat_intel_store initializes DB tables (cert_checks table exists)
    tis._ensure_db(dbp)
    # Ensure the cert_checks module picks up the test DB path when imported
    try:
        import importlib
        import src.integrations.cert_checks as _cc
        importlib.reload(_cc)
        # Rebind cc to the reloaded module to avoid stale references
        from src.integrations import cert_checks as cc  # rebind
    except Exception:
        pass

    cert = 'bad-cert-123'
    cc.queue_cert_check(cert)
    # Run worker one-shot (non-background) to process queue
    cc.start_worker(background=False)
    res = cc.get_cert_check(cert)
    assert res is not None
    assert 'status' in res


def test_cert_check_ttl(monkeypatch, tmp_path):
    dbp = str(tmp_path / 'ti.sqlite')
    monkeypatch.setenv('THREAT_INTEL_DB_PATH', dbp)
    tis._ensure_db(dbp)
    # Ensure module-level DB path is refreshed after env change
    try:
        import importlib
        import src.integrations.cert_checks as _cc
        importlib.reload(_cc)
        from src.integrations import cert_checks as cc
    except Exception:
        pass
    cert = 'good-cert-001'
    cc.queue_cert_check(cert)
    cc.start_worker(background=False)
    res = cc.get_cert_check(cert)
    assert res is not None
    # Simulate TTL expiry by setting last_checked far in past
    conn = cc._conn(); cur = conn.cursor()
    cur.execute('UPDATE cert_checks SET last_checked=? WHERE certfp=?', (0, cert))
    conn.commit(); conn.close()
    expired = cc.get_cert_check(cert)
    assert expired is None
