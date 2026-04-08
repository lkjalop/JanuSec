"""
Kafka Producer (P2)
Async Kafka producer that publishes JanuSec pipeline outputs (decisions, alerts,
normalized events) to the appropriate Kafka topics.

Falls back gracefully when confluent-kafka is not installed or Kafka is disabled,
so this module can be imported in all environments without errors.

Usage:
    from src.queue.kafka_producer import get_producer, publish_decision
    await publish_decision(decision_dict, tenant_id='acme')
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any

logger = logging.getLogger(__name__)


def _get_settings():
    try:
        from src.config.kafka_settings import settings
        return settings
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Synchronous producer wrapper (confluent-kafka is sync; we run in executor)
# ---------------------------------------------------------------------------

class _KafkaProducerWrapper:
    def __init__(self) -> None:
        self._producer: Any = None
        self._settings = _get_settings()
        self._ready = False
        self._init()

    def _init(self) -> None:
        if not self._settings or not self._settings.enabled:
            logger.info('kafka_producer: Kafka disabled (KAFKA_ENABLED not set)')
            return
        try:
            from confluent_kafka import Producer  # type: ignore
            self._producer = Producer(self._settings.producer_config())
            self._ready = True
            logger.info('kafka_producer: connected to %s', self._settings.bootstrap_servers)
        except ImportError:
            logger.warning('kafka_producer: confluent-kafka not installed; Kafka producer disabled')
        except Exception as exc:
            logger.error('kafka_producer: init failed: %s', exc)

    def send(self, topic: str, value: dict, key: str | None = None) -> None:
        """Produce a message (sync, call from executor)."""
        if not self._ready or not self._producer:
            return
        try:
            payload = json.dumps(value, default=str).encode('utf-8')
            key_bytes = key.encode('utf-8') if key else None
            self._producer.produce(
                topic,
                value=payload,
                key=key_bytes,
                callback=self._delivery_report,
            )
            # Poll to trigger delivery reports and flush the internal queue
            self._producer.poll(0)
        except Exception as exc:
            logger.error('kafka_producer: produce failed topic=%s: %s', topic, exc)

    def flush(self, timeout: float = 5.0) -> None:
        if self._ready and self._producer:
            self._producer.flush(timeout=timeout)

    @staticmethod
    def _delivery_report(err: Any, msg: Any) -> None:
        if err:
            logger.error('kafka_producer: delivery failed topic=%s: %s', msg.topic(), err)
        else:
            logger.debug('kafka_producer: delivered to %s [%d] @%d',
                         msg.topic(), msg.partition(), msg.offset())


_producer_instance: _KafkaProducerWrapper | None = None


def _get_producer_instance() -> _KafkaProducerWrapper:
    global _producer_instance
    if _producer_instance is None:
        _producer_instance = _KafkaProducerWrapper()
    return _producer_instance


def get_producer() -> _KafkaProducerWrapper:
    return _get_producer_instance()


# ---------------------------------------------------------------------------
# Async publish helpers
# ---------------------------------------------------------------------------

async def _publish(topic_short: str, payload: dict, key: str | None = None) -> bool:
    """Publish a dict to a Kafka topic (async, runs produce in executor)."""
    inst = _get_producer_instance()
    if not inst._ready:
        return False
    settings = _get_settings()
    full_topic = settings.topic(topic_short) if settings else topic_short
    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(None, lambda: inst.send(full_topic, payload, key))
        return True
    except Exception as exc:
        logger.error('kafka_producer: async publish failed: %s', exc)
        return False


async def publish_decision(decision: dict, tenant_id: str = 'default') -> bool:
    """Publish a pipeline DecisionV2 to the decisions topic."""
    key = f'{tenant_id}:{decision.get("event_id", "")}'
    return await _publish('decisions', decision, key=key)


async def publish_normalized(event: dict, tenant_id: str = 'default') -> bool:
    """Publish a normalized EventV2 to the normalized topic (pre-pipeline)."""
    key = f'{tenant_id}:{event.get("event_id", "")}'
    return await _publish('normalized', event, key=key)


async def publish_alert(alert: dict, tenant_id: str = 'default') -> bool:
    """Publish a high-confidence alert to the alerts topic."""
    key = f'{tenant_id}:{alert.get("event_id", "")}'
    return await _publish('alerts', alert, key=key)


async def publish_audit(record: dict) -> bool:
    """Append an immutable audit record to the audit topic."""
    record.setdefault('audit_ts', time.time())
    return await _publish('audit', record, key=str(record.get('audit_ts', '')))
