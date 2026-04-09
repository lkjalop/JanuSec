from __future__ import annotations

import pytest

from src.queue.kafka_assessment_queue import build_assessment_job, enqueue_assessment_request, estimate_tenant_partition


def test_estimate_tenant_partition_is_stable():
    first = estimate_tenant_partition('tenant-a', partition_count=16)
    second = estimate_tenant_partition('tenant-a', partition_count=16)
    other = estimate_tenant_partition('tenant-b', partition_count=16)
    assert first == second
    assert 0 <= first < 16
    assert 0 <= other < 16


def test_build_assessment_job_sets_tenant_partition_and_dedupe():
    job = build_assessment_job({'org': 'tenant-a', 'rows': [{'row_index': 1}]}, tenant_id='tenant-a')
    assert job['tenant_id'] == 'tenant-a'
    assert job['assessment_id']
    assert isinstance(job['partition_hint'], int)
    assert job['dedupe_key'].startswith('tenant-a:')
    assert job['payload']['org'] == 'tenant-a'


@pytest.mark.asyncio
async def test_enqueue_assessment_request_uses_assessment_topic(monkeypatch):
    calls = {}

    async def _fake_publish(payload, tenant_id='default', assessment_id=None):
        calls['payload'] = payload
        calls['tenant_id'] = tenant_id
        calls['assessment_id'] = assessment_id
        return True

    monkeypatch.setattr('src.queue.kafka_assessment_queue.publish_assessment_request', _fake_publish)
    job = await enqueue_assessment_request({'rows': [{'row_index': 1}]}, tenant_id='tenant-z', assessment_id='aid-1')
    assert job['published'] is True
    assert calls['tenant_id'] == 'tenant-z'
    assert calls['assessment_id'] == 'aid-1'
    assert calls['payload']['assessment_id'] == 'aid-1'
