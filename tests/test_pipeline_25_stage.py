import os
import asyncio
from src.core.pipeline.stages import start_pipeline_run, stage, snapshot
from src.api.metrics_tenant_helper import emit_labels_with_guard, with_tenant_label


def test_pipeline_25_stage_emission(monkeypatch, tmp_path):
    # ensure tenant cap high for first run
    monkeypatch.setenv('METRICS_MAX_TENANTS', '100')
    run_id = start_pipeline_run(tenant='tenant-p25')
    # simulate 25 stages
    for i in range(25):
        sname = f'stage-{i+1}'
        with stage(run_id, sname):
            pass
    snap = snapshot(run_id)
    assert snap is not None
    assert len(snap['stages']) == 25
    # emit labels should include tenant when under cap
    labels = emit_labels_with_guard(None, {'stage': 't'}, 'tenant-p25')
    assert labels.get('tenant') == 'tenant-p25'


def test_pipeline_suppresses_tenant_label_when_over_cap(monkeypatch):
    monkeypatch.setenv('METRICS_MAX_TENANTS', '1')
    # Create fake runtime with many tenants to exceed cap
    class R: pass
    r = R()
    r.tenants = {f't{i}': {} for i in range(5)}
    got = with_tenant_label(r, {'stage':'x'}, 'tenant-over')
    # with_tenant_label should return base (no tenant key) when cap exceeded
    assert 'tenant' not in got
