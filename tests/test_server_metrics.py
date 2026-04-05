import os
from prometheus_client import CollectorRegistry, Counter, Histogram
from src.api.metrics_guard import tenant_label_for


def test_metric_creation_with_tenant_whitelist(monkeypatch):
    # ensure whitelist path returns raw tenant label
    monkeypatch.setenv('ENABLE_TENANT_METRICS', '1')
    monkeypatch.setenv('TENANT_METRICS_WHITELIST', 'acme')
    # simulate label resolution
    t = tenant_label_for('acme')
    assert t == 'acme'

def test_metric_buckets_and_labels(monkeypatch):
    monkeypatch.setenv('ENABLE_TENANT_METRICS', '1')
    monkeypatch.setenv('TENANT_METRICS_HASH_BUCKETS', '5')
    # build registry-local metrics
    reg = CollectorRegistry()
    h = Histogram('test_hist_seconds', 'test', ['depth_bucket','tenant'], registry=reg)
    c = Counter('test_counter_total', 'test', ['result','tenant'], registry=reg)
    # label usage should not raise
    db = '4-6'
    tlabel = tenant_label_for('some-tenant')
    h.labels(depth_bucket=db, tenant=tlabel).observe(0.01)
    c.labels(result='success', tenant=tlabel).inc()
    # ensure registry contains the metric names
    names = {fam.name for fam in reg.collect()}
    # Prometheus client may register counters with or without a trailing
    # `_total` suffix depending on CollectorRegistry version; accept either.
    assert 'test_hist_seconds' in names
    assert ('test_counter_total' in names) or ('test_counter' in names)
