"""
Kinesis Shard Consumer (P0)
Async consumer for AWS Kinesis Data Streams with checkpoint persistence,
sequence-number resume, and Enhanced Fan-Out (EFO) support.

One KinesisShardConsumer task per shard is spawned by KinesisManager.
Events are normalized to EventV2 canonical envelopes and pushed to Redis
ingest_stream for downstream pipeline processing.

Env vars:
    KINESIS_STREAM_NAME         — stream name (required to activate)
    KINESIS_REGION              — AWS region (default us-east-1)
    KINESIS_CONSUMER_NAME       — EFO consumer name (default 'janusec-pipeline')
    KINESIS_USE_EFO             — '1' to enable Enhanced Fan-Out (default 0)
    KINESIS_POLL_INTERVAL_MS    — polling interval in ms (default 1000)
    KINESIS_BATCH_SIZE          — records per GetRecords call (1-10000, default 100)
    KINESIS_CHECKPOINT_DIR      — directory for sequence number checkpoints
    KINESIS_SHARD_ITERATOR_TYPE — TRIM_HORIZON | LATEST | AT_SEQUENCE_NUMBER (default TRIM_HORIZON)
    KINESIS_TENANT_ID           — tenant tag applied to envelopes (default 'aws')
    REDIS_URL                   — Redis for XADD (default redis://localhost:6379)
    REDIS_INGEST_STREAM         — stream key (default ingest_stream)
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import pathlib
import time
import uuid
from typing import Any, Callable, Awaitable

logger = logging.getLogger(__name__)

try:
    import boto3 as _boto3  # type: ignore
    _BOTO3_AVAILABLE = True
except ImportError:
    _boto3 = None  # type: ignore[assignment]
    _BOTO3_AVAILABLE = False

_STREAM_NAME = os.getenv('KINESIS_STREAM_NAME', '')
_REGION = os.getenv('KINESIS_REGION', 'us-east-1')
_CONSUMER_NAME = os.getenv('KINESIS_CONSUMER_NAME', 'janusec-pipeline')
_USE_EFO = os.getenv('KINESIS_USE_EFO', '0') in ('1', 'true', 'yes')
_POLL_INTERVAL_MS = max(200, int(os.getenv('KINESIS_POLL_INTERVAL_MS', '1000')))
_BATCH_SIZE = max(1, min(10000, int(os.getenv('KINESIS_BATCH_SIZE', '100'))))
_CHECKPOINT_DIR = pathlib.Path(os.getenv('KINESIS_CHECKPOINT_DIR', 'data/kinesis_checkpoints'))
_ITERATOR_TYPE = os.getenv('KINESIS_SHARD_ITERATOR_TYPE', 'TRIM_HORIZON')
_TENANT_ID = os.getenv('KINESIS_TENANT_ID', 'aws')
_REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379')
_INGEST_STREAM = os.getenv('REDIS_INGEST_STREAM', 'ingest_stream')


# ---------------------------------------------------------------------------
# Normaliser — Kinesis record → EventV2 canonical envelope
# ---------------------------------------------------------------------------

def _decode_kinesis_data(raw_bytes: bytes) -> dict:
    """Try to parse record Data as JSON; fallback to raw string payload."""
    try:
        return json.loads(raw_bytes.decode('utf-8'))
    except Exception:
        try:
            # Some producers base64-encode their payload twice
            return json.loads(base64.b64decode(raw_bytes).decode('utf-8'))
        except Exception:
            return {'raw_body': raw_bytes.decode('utf-8', errors='replace')}


def normalise_kinesis_record(record: dict, shard_id: str) -> dict:
    """Convert a Kinesis record to an EventV2 canonical envelope."""
    raw_data = _decode_kinesis_data(record.get('Data', b''))
    arrival = record.get('ApproximateArrivalTimestamp')
    valid_time = arrival.isoformat() if hasattr(arrival, 'isoformat') else str(arrival or '')

    # Detect well-known upstream sources
    source = raw_data.get('source') or raw_data.get('detail-type') or 'kinesis'
    event_type = raw_data.get('type') or raw_data.get('detail-type') or 'kinesis_event'

    return {
        'v': 2,
        'event_id': str(uuid.uuid4()),
        'sequence_number': record.get('SequenceNumber', ''),
        'tenant_id': _TENANT_ID,
        'ingest_ts': time.time(),
        'valid_time_start': valid_time,
        'tx_time_start': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'connector': 'kinesis',
        'shard_id': shard_id,
        'source': source,
        'event_type': event_type,
        'raw': raw_data,
    }


# ---------------------------------------------------------------------------
# Checkpoint helpers
# ---------------------------------------------------------------------------

def _checkpoint_path(stream_name: str, shard_id: str) -> pathlib.Path:
    _CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
    safe_stream = stream_name.replace('/', '_').replace(':', '_')
    return _CHECKPOINT_DIR / f'{safe_stream}__{shard_id}.seq'


def _load_checkpoint(stream_name: str, shard_id: str) -> str | None:
    path = _checkpoint_path(stream_name, shard_id)
    try:
        return path.read_text().strip() or None
    except FileNotFoundError:
        return None


def _save_checkpoint(stream_name: str, shard_id: str, seq: str) -> None:
    _checkpoint_path(stream_name, shard_id).write_text(seq)


# ---------------------------------------------------------------------------
# Redis push
# ---------------------------------------------------------------------------

async def _push_to_redis(envelope: dict) -> bool:
    try:
        import redis.asyncio as aioredis  # type: ignore
        r = aioredis.from_url(_REDIS_URL, decode_responses=True)
        await r.xadd(_INGEST_STREAM, {'data': json.dumps(envelope, default=str)})
        await r.aclose()
        return True
    except Exception as exc:
        logger.warning('kinesis_consumer: redis push failed: %s', exc)
        return False


# ---------------------------------------------------------------------------
# Shard consumer — standard polling path
# ---------------------------------------------------------------------------

class KinesisShardConsumer:
    """Consume a single Kinesis shard with automatic sequence-number checkpointing."""

    def __init__(
        self,
        stream_name: str,
        shard_id: str,
        on_record: Callable[[dict], Awaitable[bool]] | None = None,
        iterator_type: str = _ITERATOR_TYPE,
        poll_interval_ms: int = _POLL_INTERVAL_MS,
        batch_size: int = _BATCH_SIZE,
        region: str = _REGION,
    ) -> None:
        self.stream_name = stream_name
        self.shard_id = shard_id
        self.on_record = on_record or _push_to_redis
        self.iterator_type = iterator_type
        self.poll_interval_ms = poll_interval_ms
        self.batch_size = batch_size
        self.region = region
        self._running = False
        self._shard_iterator: str | None = None

    @staticmethod
    def check_ready() -> tuple[bool, str]:
        """Return (ok, message) — call at startup to surface missing dependencies."""
        if not _BOTO3_AVAILABLE:
            return False, 'boto3 not installed; pip install boto3'
        if not _STREAM_NAME:
            return False, 'KINESIS_STREAM_NAME env var not set'
        return True, 'ok'

    async def run(self) -> None:
        """Poll-based shard consumption loop."""
        if not _BOTO3_AVAILABLE:
            raise ImportError(
                'kinesis_consumer: boto3 is required but not installed. '
                f'pip install boto3  (KINESIS_STREAM_NAME={_STREAM_NAME!r} is configured)'
            )

        client = _boto3.client('kinesis', region_name=self.region)
        loop = asyncio.get_event_loop()

        # Determine starting iterator
        checkpoint = _load_checkpoint(self.stream_name, self.shard_id)
        start_kwargs: dict[str, Any] = {
            'StreamName': self.stream_name,
            'ShardId': self.shard_id,
        }
        if checkpoint:
            start_kwargs['ShardIteratorType'] = 'AFTER_SEQUENCE_NUMBER'
            start_kwargs['StartingSequenceNumber'] = checkpoint
            logger.info('kinesis_consumer: shard %s resuming after seq %s', self.shard_id, checkpoint)
        else:
            start_kwargs['ShardIteratorType'] = self.iterator_type

        resp = await loop.run_in_executor(
            None, lambda: client.get_shard_iterator(**start_kwargs)
        )
        self._shard_iterator = resp['ShardIterator']
        self._running = True

        consecutive_empty = 0
        while self._running and self._shard_iterator:
            try:
                result = await loop.run_in_executor(
                    None,
                    lambda it=self._shard_iterator: client.get_records(
                        ShardIterator=it, Limit=self.batch_size
                    ),
                )
            except Exception as exc:
                logger.error('kinesis_consumer: get_records failed shard %s: %s', self.shard_id, exc)
                await asyncio.sleep(5)
                continue

            records = result.get('Records', [])
            self._shard_iterator = result.get('NextShardIterator')

            if records:
                consecutive_empty = 0
                last_seq = ''
                for rec in records:
                    envelope = normalise_kinesis_record(rec, self.shard_id)
                    try:
                        await self.on_record(envelope)
                    except Exception as exc:
                        logger.error('kinesis_consumer: on_record failed: %s', exc)
                    last_seq = rec.get('SequenceNumber', '')
                if last_seq:
                    _save_checkpoint(self.stream_name, self.shard_id, last_seq)
            else:
                consecutive_empty += 1

            # Adaptive back-off when idle (up to 5s between empty polls)
            sleep_s = min(5.0, (self.poll_interval_ms / 1000) * (1 + consecutive_empty * 0.1))
            await asyncio.sleep(sleep_s)

        logger.info('kinesis_consumer: shard %s poll loop exited', self.shard_id)

    def stop(self) -> None:
        self._running = False


# ---------------------------------------------------------------------------
# Enhanced Fan-Out consumer
# ---------------------------------------------------------------------------

class KinesisEFOConsumer:
    """
    Enhanced Fan-Out consumer: dedicated 2 MB/s read throughput per consumer.
    Best for high-throughput shards or multiple parallel consumer groups.
    """

    def __init__(
        self,
        stream_name: str,
        shard_id: str,
        consumer_arn: str,
        on_record: Callable[[dict], Awaitable[bool]] | None = None,
        region: str = _REGION,
    ) -> None:
        self.stream_name = stream_name
        self.shard_id = shard_id
        self.consumer_arn = consumer_arn
        self.on_record = on_record or _push_to_redis
        self.region = region
        self._running = False

    async def run(self) -> None:
        """Subscribe to shard via push-based EventStream."""
        try:
            import aioboto3  # type: ignore
        except ImportError:
            logger.warning(
                'kinesis_consumer: aioboto3 not installed; EFO shard %s falling back to polling',
                self.shard_id,
            )
            # Graceful fall-back to standard polling
            fallback = KinesisShardConsumer(
                self.stream_name, self.shard_id, self.on_record, region=self.region
            )
            await fallback.run()
            return

        self._running = True
        checkpoint = _load_checkpoint(self.stream_name, self.shard_id)
        starting_position: dict[str, Any] = {'Type': 'TRIM_HORIZON'}
        if checkpoint:
            starting_position = {
                'Type': 'AFTER_SEQUENCE_NUMBER',
                'SequenceNumber': checkpoint,
            }

        session = aioboto3.Session()
        async with session.client('kinesis', region_name=self.region) as client:
            try:
                async with client.subscribe_to_shard(
                    ConsumerARN=self.consumer_arn,
                    ShardId=self.shard_id,
                    StartingPosition=starting_position,
                ) as stream:
                    async for event_batch in stream['EventStream']:
                        if not self._running:
                            break
                        for rec in event_batch.get('Records', []):
                            envelope = normalise_kinesis_record(rec, self.shard_id)
                            try:
                                await self.on_record(envelope)
                            except Exception as exc:
                                logger.error('kinesis_efo: on_record failed: %s', exc)
                            seq = rec.get('SequenceNumber', '')
                            if seq:
                                _save_checkpoint(self.stream_name, self.shard_id, seq)
            except Exception as exc:
                logger.error('kinesis_efo: subscribe_to_shard failed shard %s: %s', self.shard_id, exc)

    def stop(self) -> None:
        self._running = False
