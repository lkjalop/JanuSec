import os
from src.api.metrics_guard import tenant_label_for


def test_tenant_label_default():
    assert tenant_label_for(None) == 'default'
    assert tenant_label_for('') == 'default'


def test_tenant_whitelist(monkeypatch):
    monkeypatch.setenv('TENANT_METRICS_WHITELIST', 'acme,bluecorp')
    assert tenant_label_for('acme') == 'acme'
    assert tenant_label_for('bluecorp') == 'bluecorp'
    # non-whitelisted falls back to other or bucket (depending on buckets env)


def test_hash_buckets(monkeypatch):
    monkeypatch.delenv('TENANT_METRICS_WHITELIST', raising=False)
    monkeypatch.setenv('TENANT_METRICS_HASH_BUCKETS', '10')
    # deterministic bucket prefix
    lbl = tenant_label_for('tenant-123')
    assert lbl.startswith('b')
