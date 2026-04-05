import os
from src.api.metrics_tenant_helper import emit_labels_with_guard

class DummyRuntime:
    def __init__(self, tenants):
        self.tenants = tenants

def test_emit_labels_with_guard_under_cap():
    os.environ['METRICS_MAX_TENANTS'] = '5'
    rt = DummyRuntime({'t1': {}, 't2': {}})
    labels = emit_labels_with_guard(rt, {'result': 'ok'}, 't3')
    assert 'tenant' in labels and labels['tenant'] == 't3'


def test_emit_labels_with_guard_over_cap():
    os.environ['METRICS_MAX_TENANTS'] = '2'
    rt = DummyRuntime({'t1': {}, 't2': {}, 'tX': {}})
    labels = emit_labels_with_guard(rt, {'result': 'ok'}, 't4')
    # tenant should be suppressed -> empty string after normalization
    assert 'tenant' in labels and labels['tenant'] == ''


def test_emit_labels_with_guard_no_tenant():
    os.environ['METRICS_MAX_TENANTS'] = '50'
    rt = DummyRuntime({'t1': {}})
    labels = emit_labels_with_guard(rt, {'result': 'ok'}, None)
    assert 'tenant' in labels and labels['tenant'] == ''
