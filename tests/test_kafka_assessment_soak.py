from __future__ import annotations

from scripts.kafka_assessment_soak import run_assessment_soak


def test_kafka_assessment_soak_surfaces_ransomware_ddos_and_benign_marketing(monkeypatch):
    monkeypatch.setenv('LLM_MOCK', '1')
    report = run_assessment_soak(employee_count=120, iterations=1, worker_parallelism=2)

    assert report['processed_jobs'] >= 5
    assert report['tenant_isolation_ok'] is True
    assert report['latency_p95_ms'] > 0
    assert report['queue_depth_p95'] > 0
    assert report['worker_stats']['processed'] >= 5
    assert report['worker_stats']['deduped'] >= 1

    by_scenario = {}
    for item in report['scenario_summaries']:
        by_scenario.setdefault(item['scenario'], []).append(item)

    assert 'ransomware' in by_scenario
    assert 'ddos_no_cdn' in by_scenario
    assert 'marketing_burst' in by_scenario

    ransomware = by_scenario['ransomware'][0]
    ddos = by_scenario['ddos_no_cdn'][0]
    marketing = max(by_scenario['marketing_burst'], key=lambda item: (item.get('cluster_count') or 0, item.get('latency_ms') or 0))

    assert ransomware['cluster_count'] >= 1
    assert ddos['cluster_count'] >= 1
    assert ransomware['top_cluster_severity'] in {'critical', 'high'}
    assert ddos['human_validation_required'] is True
    assert marketing['human_validation_required'] is True


def test_kafka_assessment_soak_recommendations_cover_long_running_pressure(monkeypatch):
    monkeypatch.setenv('LLM_MOCK', '1')
    report = run_assessment_soak(employee_count=80, iterations=1, worker_parallelism=2)
    recommendations = ' '.join(report.get('recommendations') or []).lower()
    assert '12-24h soak' in recommendations
    assert '3-day' in recommendations or '7-day' in recommendations
