from __future__ import annotations

import hashlib
import os
import time
import uuid
from typing import Any, Dict

from src.queue.kafka_producer import publish_assessment_request


def _partition_count() -> int:
    try:
        return max(1, int(os.getenv('KAFKA_ASSESSMENT_PARTITIONS', '12')))
    except Exception:
        return 12


def estimate_tenant_partition(tenant_id: str, partition_count: int | None = None) -> int:
    count = max(1, int(partition_count or _partition_count()))
    digest = hashlib.sha256((tenant_id or 'default').encode('utf-8')).hexdigest()
    return int(digest[:8], 16) % count


def build_assessment_job(
    payload: Dict[str, Any],
    tenant_id: str = 'default',
    assessment_id: str | None = None,
    source: str = 'api',
) -> Dict[str, Any]:
    aid = assessment_id or payload.get('assessment_id') or f"queued-{int(time.time())}-{uuid.uuid4().hex[:8]}"
    partition = estimate_tenant_partition(tenant_id)
    job = {
        'job_id': f'{tenant_id}:{aid}:{uuid.uuid4().hex[:6]}',
        'tenant_id': tenant_id or 'default',
        'assessment_id': aid,
        'source': source,
        'partition_hint': partition,
        'queued_at': time.time(),
        'queued_at_ms': int(time.time() * 1000),
        'payload': {
            **payload,
            'assessment_id': aid,
            'org': payload.get('org') or payload.get('tenant') or tenant_id or 'default',
        },
    }
    job['dedupe_key'] = f"{job['tenant_id']}:{job['assessment_id']}:{hashlib.sha1(str(sorted((payload.get('rows') or [])[:3], key=str)).encode('utf-8')).hexdigest()[:12]}"
    return job


async def enqueue_assessment_request(
    payload: Dict[str, Any],
    tenant_id: str = 'default',
    assessment_id: str | None = None,
    source: str = 'api',
) -> Dict[str, Any]:
    job = build_assessment_job(payload, tenant_id=tenant_id, assessment_id=assessment_id, source=source)
    ok = await publish_assessment_request(job, tenant_id=job['tenant_id'], assessment_id=job['assessment_id'])
    job['published'] = bool(ok)
    return job
