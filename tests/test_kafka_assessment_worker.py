from __future__ import annotations

import pytest
from fastapi.responses import JSONResponse

from src.workers.kafka_assessment_worker import KafkaAssessmentWorker


@pytest.mark.asyncio
async def test_kafka_assessment_worker_processes_and_publishes(monkeypatch):
    published = []
    audits = []

    async def _fake_run(payload):
        return JSONResponse({'assessment_id': payload.get('assessment_id'), 'status': 'pending', 'evidence_rows': [], 'correlation_clusters': []})

    async def _fake_publish_result(payload, tenant_id='default', assessment_id=None):
        published.append((tenant_id, assessment_id, payload))
        return True

    async def _fake_publish_audit(record):
        audits.append(record)
        return True

    monkeypatch.setattr('src.api.deep_analyze_endpoints.run_deep_analyze_pipeline', _fake_run)
    monkeypatch.setattr('src.workers.kafka_assessment_worker.publish_assessment_result', _fake_publish_result)
    monkeypatch.setattr('src.workers.kafka_assessment_worker.publish_audit', _fake_publish_audit)

    worker = KafkaAssessmentWorker()
    ok, result = await worker.process_job(
        {
            'tenant_id': 'tenant-a',
            'assessment_id': 'aid-1',
            'dedupe_key': 'tenant-a:aid-1:abc',
            'payload': {'assessment_id': 'aid-1', 'org': 'tenant-a', 'rows': []},
        },
        'janusec.assessment.requests',
        1,
        42,
    )
    assert ok is True
    assert result['assessment_id'] == 'aid-1'
    assert published and published[0][0] == 'tenant-a'
    assert audits and audits[0]['assessment_id'] == 'aid-1'


@pytest.mark.asyncio
async def test_kafka_assessment_worker_dedupes_same_job(monkeypatch):
    async def _fake_run(payload):
        return JSONResponse({'assessment_id': payload.get('assessment_id'), 'status': 'pending'})

    async def _fake_publish_result(payload, tenant_id='default', assessment_id=None):
        return True

    async def _fake_publish_audit(record):
        return True

    monkeypatch.setattr('src.api.deep_analyze_endpoints.run_deep_analyze_pipeline', _fake_run)
    monkeypatch.setattr('src.workers.kafka_assessment_worker.publish_assessment_result', _fake_publish_result)
    monkeypatch.setattr('src.workers.kafka_assessment_worker.publish_audit', _fake_publish_audit)

    worker = KafkaAssessmentWorker()
    payload = {
        'tenant_id': 'tenant-a',
        'assessment_id': 'aid-dup',
        'dedupe_key': 'tenant-a:aid-dup:xyz',
        'payload': {'assessment_id': 'aid-dup', 'org': 'tenant-a', 'rows': []},
    }
    ok1, result1 = await worker.process_job(payload, 'janusec.assessment.requests', 0, 1)
    ok2, result2 = await worker.process_job(payload, 'janusec.assessment.requests', 0, 2)
    stats = worker.get_stats()
    assert ok1 is True
    assert ok2 is True
    assert result1['assessment_id'] == 'aid-dup'
    assert result2['status'] == 'deduped'
    assert stats['deduped'] >= 1
