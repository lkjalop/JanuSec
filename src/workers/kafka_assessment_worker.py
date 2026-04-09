from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import time
from collections import deque
from typing import Any

from src.queue.kafka_consumer import KafkaConsumerGroup
from src.queue.kafka_producer import publish_assessment_result, publish_audit

logger = logging.getLogger(__name__)

_CONCURRENCY = max(1, int(os.getenv('KAFKA_ASSESSMENT_WORKER_CONCURRENCY', '3')))
_MAX_DEDUPE = max(100, int(os.getenv('KAFKA_ASSESSMENT_WORKER_DEDUPE_SIZE', '5000')))


def _get_settings():
    try:
        from src.config.kafka_settings import settings
        return settings
    except Exception:
        return None


def _response_to_dict(resp: Any) -> dict:
    if resp is None:
        return {}
    if isinstance(resp, dict):
        return resp
    body = getattr(resp, 'body', b'') or b''
    if isinstance(body, bytes):
        try:
            return json.loads(body.decode('utf-8'))
        except Exception:
            return {}
    return {}


class KafkaAssessmentWorker:
    """Consumes assessment jobs from Kafka and runs deep-analyze with tenant-keyed fan-out."""

    def __init__(self) -> None:
        self._settings = _get_settings()
        self._running = False
        self._semaphore = asyncio.Semaphore(_CONCURRENCY)
        self._seen: set[str] = set()
        self._seen_order: deque[str] = deque()
        self._stats = {
            'consumed': 0,
            'processed': 0,
            'deduped': 0,
            'errors': 0,
            'published': 0,
            'tenants': set(),
            'started_at': time.time(),
            'last_message_at': 0.0,
            'latencies_ms': [],
        }

    def _remember_dedupe(self, dedupe_key: str) -> bool:
        if dedupe_key in self._seen:
            return True
        self._seen.add(dedupe_key)
        self._seen_order.append(dedupe_key)
        while len(self._seen_order) > _MAX_DEDUPE:
            old = self._seen_order.popleft()
            self._seen.discard(old)
        return False

    async def process_job(self, payload: dict, topic: str, partition: int, offset: int) -> tuple[bool, dict]:
        tenant = str(payload.get('tenant_id') or payload.get('payload', {}).get('org') or 'default')
        self._stats['tenants'].add(tenant)
        dedupe_key = str(payload.get('dedupe_key') or '')
        if dedupe_key and self._remember_dedupe(dedupe_key):
            self._stats['deduped'] += 1
            return True, {'status': 'deduped', 'tenant_id': tenant, 'assessment_id': payload.get('assessment_id')}

        try:
            from src.api.deep_analyze_endpoints import run_deep_analyze_pipeline
            job_payload = payload.get('payload') if isinstance(payload.get('payload'), dict) else payload
            response = await run_deep_analyze_pipeline(job_payload)
            result = _response_to_dict(response)
            result.setdefault('tenant_id', tenant)
            result.setdefault('queue_meta', {
                'source_topic': topic,
                'partition': partition,
                'offset': offset,
                'worker': 'kafka_assessment_worker',
            })
            await publish_assessment_result(result, tenant_id=tenant, assessment_id=result.get('assessment_id'))
            await publish_audit({
                'kind': 'assessment_worker_result',
                'tenant_id': tenant,
                'assessment_id': result.get('assessment_id'),
                'source_topic': topic,
                'partition': partition,
                'offset': offset,
            })
            self._stats['processed'] += 1
            self._stats['published'] += 1
            return True, result
        except Exception as exc:
            logger.error('kafka_assessment_worker: processing error: %s', exc)
            self._stats['errors'] += 1
            return False, {'status': 'error', 'tenant_id': tenant, 'error': str(exc)}

    async def handle(self, payload: dict, topic: str, partition: int, offset: int) -> bool:
        async with self._semaphore:
            started = time.perf_counter()
            try:
                self._stats['consumed'] += 1
                self._stats['last_message_at'] = time.time()
                ok, _ = await self.process_job(payload, topic, partition, offset)
                return ok
            finally:
                latency_ms = round((time.perf_counter() - started) * 1000.0, 2)
                self._stats['latencies_ms'].append(latency_ms)
                self._stats['latencies_ms'] = self._stats['latencies_ms'][-2000:]

    def get_stats(self) -> dict:
        latencies = list(self._stats.get('latencies_ms') or [])
        p95 = 0.0
        if latencies:
            ordered = sorted(latencies)
            idx = min(len(ordered) - 1, max(0, int(len(ordered) * 0.95) - 1))
            p95 = float(ordered[idx])
        return {
            **self._stats,
            'tenants': sorted(self._stats.get('tenants') or []),
            'latency_p95_ms': round(p95, 2),
        }

    async def run(self) -> None:
        settings = self._settings
        topics = [getattr(settings, 'assessment_topic', 'janusec.assessment.requests')]
        consumer = KafkaConsumerGroup(
            topics=topics,
            on_message=self.handle,
            group_id=os.getenv('KAFKA_ASSESSMENT_CONSUMER_GROUP', 'janusec.assessment-workers'),
        )
        self._running = True
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, self.stop)
            except NotImplementedError:
                pass

        await consumer.start()
        try:
            while self._running:
                await asyncio.sleep(5)
        finally:
            await consumer.stop()

    def stop(self) -> None:
        self._running = False


async def _main() -> None:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)s %(levelname)s: %(message)s')
    worker = KafkaAssessmentWorker()
    await worker.run()


if __name__ == '__main__':
    asyncio.run(_main())
