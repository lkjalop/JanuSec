"""
Kafka Consumer (P2)
Async consumer group wrapper that reads from one or more Kafka topics,
applies per-message processing, and commits offsets only after successful
handling.  Used by the Kafka pipeline worker and other specialised consumers.

Falls back gracefully when confluent-kafka is not installed or Kafka is disabled.

Usage:
    from src.queue.kafka_consumer import KafkaConsumerGroup
    consumer = KafkaConsumerGroup(topics=['janusec.normalized'], on_message=handler)
    await consumer.start()
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, Callable, Awaitable

logger = logging.getLogger(__name__)


def _get_settings():
    try:
        from src.config.kafka_settings import settings
        return settings
    except Exception:
        return None


class KafkaConsumerGroup:
    """Async wrapper around a confluent-kafka Consumer that polls in an executor."""

    def __init__(
        self,
        topics: list[str] | None = None,
        on_message: Callable[[dict, str, int, int], Awaitable[bool]] | None = None,
        group_id: str | None = None,
    ) -> None:
        """
        Args:
            topics:      List of Kafka topic names to subscribe to.
            on_message:  Async callback(payload_dict, topic, partition, offset) → bool.
                         Return True to commit, False to leave uncommitted.
            group_id:    Override the consumer group ID.
        """
        self._settings = _get_settings()
        self._topics = topics or (
            [self._settings.input_topic] if self._settings else ['janusec.normalized']
        )
        self.group_id = group_id or (self._settings.consumer_group if self._settings else 'janusec.pipeline-workers')
        self.on_message = on_message or self._default_handler
        self._consumer: Any = None
        self._running = False
        self._task: asyncio.Task | None = None

    @staticmethod
    async def _default_handler(payload: dict, topic: str, partition: int, offset: int) -> bool:
        logger.debug('kafka_consumer: consumed %s p%d @%d', topic, partition, offset)
        return True

    def _build_consumer(self) -> Any | None:
        if not self._settings or not self._settings.enabled:
            return None
        try:
            from confluent_kafka import Consumer  # type: ignore
            cfg = self._settings.consumer_config(self.group_id)
            c = Consumer(cfg)
            c.subscribe(self._topics)
            logger.info('kafka_consumer: subscribed to %s (group=%s)', self._topics, self.group_id)
            return c
        except ImportError:
            logger.warning('kafka_consumer: confluent-kafka not installed; consumer disabled')
            return None
        except Exception as exc:
            logger.error('kafka_consumer: init failed: %s', exc)
            return None

    async def start(self) -> None:
        self._consumer = self._build_consumer()
        if not self._consumer:
            logger.info('kafka_consumer: not started (Kafka disabled or unavailable)')
            return
        self._running = True
        self._task = asyncio.create_task(self._poll_loop(), name=f'kafka-consumer-{self.group_id}')
        logger.info('kafka_consumer: started group=%s topics=%s', self.group_id, self._topics)

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        if self._consumer:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._consumer.close)
        logger.info('kafka_consumer: stopped')

    async def _poll_loop(self) -> None:
        loop = asyncio.get_event_loop()
        poll_timeout = (self._settings.poll_timeout_ms if self._settings else 1000) / 1000

        while self._running:
            try:
                msg = await loop.run_in_executor(
                    None, lambda: self._consumer.poll(poll_timeout)
                )
            except Exception as exc:
                logger.error('kafka_consumer: poll error: %s', exc)
                await asyncio.sleep(1)
                continue

            if msg is None:
                continue

            if msg.error():
                # End of partition is not an error in newer versions; handle gracefully
                from confluent_kafka import KafkaError  # type: ignore
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                logger.error('kafka_consumer: message error: %s', msg.error())
                continue

            try:
                raw = msg.value()
                payload = json.loads(raw.decode('utf-8')) if raw else {}
            except Exception as exc:
                logger.error('kafka_consumer: decode failed: %s', exc)
                # Commit anyway to avoid replay loop on bad messages
                await loop.run_in_executor(None, self._consumer.commit, msg)
                continue

            try:
                success = await self.on_message(
                    payload, msg.topic(), msg.partition(), msg.offset()
                )
            except Exception as exc:
                logger.error('kafka_consumer: on_message raised: %s', exc)
                success = False

            if success:
                await loop.run_in_executor(None, self._consumer.commit, msg)

        logger.info('kafka_consumer: poll loop exited')

    def get_lag(self) -> dict[str, int]:
        """Return estimated per-topic-partition lag (requires metadata calls)."""
        if not self._consumer:
            return {}
        lag: dict[str, int] = {}
        try:
            from confluent_kafka import TopicPartition  # type: ignore
            assignment = self._consumer.assignment()
            if not assignment:
                return {}
            _, high_watermarks = self._consumer.get_watermark_offsets(assignment[0], timeout=1)
            committed = self._consumer.committed(assignment, timeout=1)
            for tp, committed_tp in zip(assignment, committed):
                _, high = self._consumer.get_watermark_offsets(tp, cached=True)
                c_offset = committed_tp.offset if committed_tp.offset >= 0 else 0
                lag[f'{tp.topic}[{tp.partition}]'] = max(0, high - c_offset)
        except Exception:
            pass
        return lag
