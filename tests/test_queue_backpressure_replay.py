from __future__ import annotations

from scripts.queue_backpressure_replay import run_queue_pressure


def test_queue_backpressure_replay_reports_pressure_and_throughput(monkeypatch):
    monkeypatch.setenv('LLM_MOCK', '1')
    report = run_queue_pressure(employee_count=200, batch_size=60, workers=3)
    assert report.get('total_batches', 0) >= 4
    assert report.get('total_rows', 0) >= 400
    assert report.get('throughput_rows_per_second', 0) > 10
    assert report.get('queue_pressure') in {'low', 'medium', 'high'}
    assert report.get('queue_lag_p95_ms', 0) >= 0
    assert report.get('batch_latency_p95_ms', 0) > 0
    assert report.get('recommendations')
    variants = {item.get('variant') for item in (report.get('batches') or [])}
    assert {'okta_aws_azure', 'ad_aws_vmware_bec'} <= variants
