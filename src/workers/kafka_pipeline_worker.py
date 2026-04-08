"""
Kafka Pipeline Worker (P2)
Standalone worker that consumes normalized events from the Kafka 'normalized'
topic, runs them through the JanuSec 27-stage event pipeline, and publishes
decisions to the 'decisions' topic.

Designed to be scaled horizontally (docker-compose scale kafka-pipeline-worker=N
or HPA in Kubernetes).  Multiple instances share a consumer group so Kafka
auto-distributes partitions.

Entry points:
    python -m src.workers.kafka_pipeline_worker           (single worker)
    KAFKA_BATCH_SIZE=50 python -m src.workers.kafka_pipeline_worker  (tuned)

Env vars (in addition to kafka_settings.py env vars):
    KAFKA_WORKER_CONCURRENCY  — async pipeline tasks per worker (default 4)
    KAFKA_WORKER_MAX_IDLE_SECS — shutdown after N idle seconds (0=never, default 0)
    PIPELINE_TIMEOUT_SECS     — per-event pipeline timeout (default 30)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
import time
from typing import Any

logger = logging.getLogger(__name__)

_CONCURRENCY = int(os.getenv('KAFKA_WORKER_CONCURRENCY', '4'))
_MAX_IDLE_SECS = int(os.getenv('KAFKA_WORKER_MAX_IDLE_SECS', '0'))
_PIPELINE_TIMEOUT = int(os.getenv('PIPELINE_TIMEOUT_SECS', '30'))


def _get_settings():
    try:
        from src.config.kafka_settings import settings
        return settings
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Pipeline invocation helper
# ---------------------------------------------------------------------------

async def _run_pipeline(event: dict) -> dict | None:
    """Call the JanuSec event pipeline on a normalised event envelope.

    Returns a DecisionV2 dict or None on error.
    """
    try:
        # Import pipeline (deferred to avoid circular imports at module level)
        from src.core.event_pipeline.pipeline import EventPipeline  # type: ignore
        pipeline = EventPipeline()
        result = await asyncio.wait_for(
            pipeline.process(event),
            timeout=_PIPELINE_TIMEOUT,
        )
        return result
    except asyncio.TimeoutError:
        logger.error('kafka_pipeline_worker: pipeline timeout for event %s',
                     event.get('event_id', '?'))
        return None
    except ImportError:
        # Pipeline not available in lite mode — pass through with stub decision
        logger.debug('kafka_pipeline_worker: EventPipeline not available; emitting stub decision')
        return {
            'event_id': event.get('event_id'),
            'tenant_id': event.get('tenant_id', 'default'),
            'verdict': 'UNDETERMINED',
            'confidence': 0.0,
            'processed_at': time.time(),
            'source_event': event,
        }
    except Exception as exc:
        logger.error('kafka_pipeline_worker: pipeline error: %s', exc)
        return None


# ---------------------------------------------------------------------------
# Message handler
# ---------------------------------------------------------------------------

class KafkaPipelineWorker:
    """Consumes from 'normalized', runs pipeline, produces to 'decisions'."""

    def __init__(self) -> None:
        self._settings = _get_settings()
        self._running = False
        self._semaphore = asyncio.Semaphore(_CONCURRENCY)
        self._stats = {
            'consumed': 0, 'decisions': 0, 'errors': 0,
            'started_at': time.time(), 'last_message_at': 0.0,
        }

    async def handle(self, payload: dict, topic: str, partition: int, offset: int) -> bool:
        """Process one event from Kafka; publish decision back."""
        async with self._semaphore:
            self._stats['consumed'] += 1
            self._stats['last_message_at'] = time.time()

            decision = await _run_pipeline(payload)
            if decision is None:
                self._stats['errors'] += 1
                return False  # don't commit — will retry

            # Publish decision to decisions topic
            try:
                from src.queue.kafka_producer import publish_decision  # local import
                tenant = decision.get('tenant_id', 'default')
                await publish_decision(decision, tenant_id=tenant)
            except Exception as exc:
                logger.error('kafka_pipeline_worker: publish_decision failed: %s', exc)
                # Still commit — decision was generated, just delivery failed
                # Producer will retry on next poll cycle

            # Fan-out high-confidence decisions to alerts topic
            confidence = float(decision.get('confidence', 0.0) or 0.0)
            verdict = str(decision.get('verdict', '')).upper()
            if confidence >= 0.80 and verdict in ('MALICIOUS', 'HIGH', 'CRITICAL'):
                try:
                    from src.queue.kafka_producer import publish_alert
                    await publish_alert(decision, tenant_id=decision.get('tenant_id', 'default'))
                except Exception:
                    pass

            self._stats['decisions'] += 1
            return True  # commit offset

    async def run(self) -> None:
        from src.queue.kafka_consumer import KafkaConsumerGroup
        settings = self._settings
        topics = [settings.input_topic] if settings else ['janusec.normalized']

        consumer = KafkaConsumerGroup(
            topics=topics,
            on_message=self.handle,
        )
        self._running = True

        # Graceful shutdown on SIGTERM/SIGINT
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, self.stop)
            except NotImplementedError:
                pass  # Windows fallback

        await consumer.start()
        logger.info('kafka_pipeline_worker: running, concurrency=%d', _CONCURRENCY)

        try:
            while self._running:
                await asyncio.sleep(5)
                if _MAX_IDLE_SECS > 0:
                    idle = time.time() - self._stats['last_message_at']
                    if self._stats['last_message_at'] > 0 and idle > _MAX_IDLE_SECS:
                        logger.info('kafka_pipeline_worker: idle %ds > max %ds, shutting down',
                                    idle, _MAX_IDLE_SECS)
                        break
                # Log heartbeat every 60s
                elapsed = time.time() - self._stats['started_at']
                if int(elapsed) % 60 < 5:
                    logger.info(
                        'kafka_pipeline_worker: stats consumed=%d decisions=%d errors=%d uptime=%.0fs',
                        self._stats['consumed'],
                        self._stats['decisions'],
                        self._stats['errors'],
                        elapsed,
                    )
        finally:
            await consumer.stop()
            logger.info('kafka_pipeline_worker: stopped. final_stats=%s', self._stats)

    def stop(self) -> None:
        logger.info('kafka_pipeline_worker: shutdown requested')
        self._running = False

    def get_stats(self) -> dict:
        return dict(self._stats)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def _main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(name)s %(levelname)s: %(message)s',
    )
    worker = KafkaPipelineWorker()
    await worker.run()


if __name__ == '__main__':
    asyncio.run(_main())
