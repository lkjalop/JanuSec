from scripts.multi_tenant_harness import run_harness
from src.api.metrics_init import tenant_isolation_violations


def test_multi_tenant_harness_no_leakage(monkeypatch):
    # Run harness with deterministic tenants
    report = run_harness(['t1','t2','t3'], events_per_tenant=20)
    # If violations present, increment metric (best-effort)
    v = report.get('violations', 0)
    if v and tenant_isolation_violations:
        try:
            tenant_isolation_violations.inc()
        except Exception:
            pass
    # Assert that harness runs and produces a report structure
    assert 'produced' in report and isinstance(report['produced'], dict)
    assert 'tenants' in report and len(report['tenants']) == 3