"""
Kinesis Manager (P0)
Discovers shards for a Kinesis stream and manages the lifecycle of per-shard
consumer tasks.  Handles shard splits/merges by periodically re-discovering
the shard list and adding/removing consumer tasks accordingly.

Usage (wire into app lifespan):
    from src.connectors.aws.kinesis_manager import KinesisManager, start_kinesis_manager
    await start_kinesis_manager(app)

Env vars:
    KINESIS_STREAM_NAME         — stream name (required to activate)
    KINESIS_REGION              — AWS region (default us-east-1)
    KINESIS_USE_EFO             — '1' to use Enhanced Fan-Out (default 0)
    KINESIS_CONSUMER_NAME       — EFO registered consumer name (default 'janusec-pipeline')
    KINESIS_SHARD_REFRESH_SECS  — interval to re-check shard list (default 300)
    KINESIS_TENANT_ID           — tenant tag for all events (default 'aws')
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

_STREAM_NAME = os.getenv('KINESIS_STREAM_NAME', '')
_REGION = os.getenv('KINESIS_REGION', 'us-east-1')
_USE_EFO = os.getenv('KINESIS_USE_EFO', '0') in ('1', 'true', 'yes')
_CONSUMER_NAME = os.getenv('KINESIS_CONSUMER_NAME', 'janusec-pipeline')
_SHARD_REFRESH_SECS = int(os.getenv('KINESIS_SHARD_REFRESH_SECS', '300'))


def _list_open_shards(client: Any, stream_name: str) -> list[str]:
    """Return shard IDs for all OPEN (non-closed) shards in the stream."""
    shards: list[str] = []
    kwargs: dict[str, Any] = {'StreamName': stream_name, 'ShardFilter': {'Type': 'FROM_TRIM_HORIZON'}}
    while True:
        try:
            resp = client.list_shards(**kwargs)
        except Exception:
            # Fall back to describe_stream for older API versions
            resp_ds = client.describe_stream(StreamName=stream_name)
            return [
                s['ShardId']
                for s in resp_ds['StreamDescription']['Shards']
                if 'EndingSequenceNumber' not in s.get('SequenceNumberRange', {})
            ]
        for shard in resp.get('Shards', []):
            # Exclude closed shards (they have an EndingSequenceNumber)
            if 'EndingSequenceNumber' not in shard.get('SequenceNumberRange', {}):
                shards.append(shard['ShardId'])
        token = resp.get('NextToken')
        if not token:
            break
        kwargs = {'NextToken': token}
    return shards


def _ensure_efo_consumer(client: Any, stream_arn: str) -> str | None:
    """Register or fetch the EFO consumer ARN for this stream."""
    try:
        resp = client.register_stream_consumer(
            StreamARN=stream_arn,
            ConsumerName=_CONSUMER_NAME,
        )
        arn = resp['Consumer']['ConsumerARN']
        logger.info('kinesis_manager: EFO consumer registered: %s', arn)
        return arn
    except client.exceptions.ResourceInUseException:
        # Already registered — look it up
        resp = client.describe_stream_consumer(
            StreamARN=stream_arn,
            ConsumerName=_CONSUMER_NAME,
        )
        return resp['Consumer']['ConsumerARN']
    except Exception as exc:
        logger.warning('kinesis_manager: EFO consumer registration failed: %s', exc)
        return None


class KinesisManager:
    """Manages a pool of per-shard consumer asyncio tasks for a Kinesis stream."""

    def __init__(
        self,
        stream_name: str = _STREAM_NAME,
        region: str = _REGION,
        use_efo: bool = _USE_EFO,
    ) -> None:
        self.stream_name = stream_name
        self.region = region
        self.use_efo = use_efo
        self._tasks: dict[str, asyncio.Task] = {}  # shard_id → task
        self._consumers: dict[str, Any] = {}       # shard_id → consumer object
        self._consumer_arn: str | None = None
        self._stream_arn: str | None = None
        self._running = False
        self._refresh_task: asyncio.Task | None = None

    async def start(self) -> None:
        if not self.stream_name:
            logger.info('kinesis_manager: KINESIS_STREAM_NAME not set — manager disabled')
            return
        self._running = True
        await self._refresh_shards()
        self._refresh_task = asyncio.create_task(self._refresh_loop())
        logger.info('kinesis_manager: started for stream %s (%d shards)',
                    self.stream_name, len(self._tasks))

    async def stop(self) -> None:
        self._running = False
        if self._refresh_task:
            self._refresh_task.cancel()
        for consumer in self._consumers.values():
            consumer.stop()
        for task in self._tasks.values():
            task.cancel()
        await asyncio.gather(*self._tasks.values(), return_exceptions=True)
        self._tasks.clear()
        self._consumers.clear()
        logger.info('kinesis_manager: stopped')

    async def _refresh_shards(self) -> None:
        """Discover shards and start consumer tasks for any new ones."""
        try:
            import boto3  # type: ignore
        except ImportError:
            logger.warning('kinesis_manager: boto3 not installed')
            return

        loop = asyncio.get_event_loop()
        client = boto3.client('kinesis', region_name=self.region)

        # Fetch stream ARN for EFO
        if self.use_efo and not self._stream_arn:
            try:
                ds = await loop.run_in_executor(
                    None, lambda: client.describe_stream_summary(StreamName=self.stream_name)
                )
                self._stream_arn = ds['StreamDescriptionSummary']['StreamARN']
                self._consumer_arn = await loop.run_in_executor(
                    None, lambda: _ensure_efo_consumer(client, self._stream_arn)
                )
            except Exception as exc:
                logger.error('kinesis_manager: stream ARN lookup failed: %s', exc)

        try:
            shard_ids = await loop.run_in_executor(
                None, lambda: _list_open_shards(client, self.stream_name)
            )
        except Exception as exc:
            logger.error('kinesis_manager: shard list failed: %s', exc)
            return

        # Start tasks for new shards
        for shard_id in shard_ids:
            if shard_id not in self._tasks or self._tasks[shard_id].done():
                await self._start_shard(shard_id)

        # Cancel tasks for shards that no longer exist (merged/split)
        gone = set(self._tasks.keys()) - set(shard_ids)
        for shard_id in gone:
            consumer = self._consumers.pop(shard_id, None)
            if consumer:
                consumer.stop()
            task = self._tasks.pop(shard_id, None)
            if task:
                task.cancel()
            logger.info('kinesis_manager: removed closed shard %s', shard_id)

    async def _start_shard(self, shard_id: str) -> None:
        from src.connectors.aws.kinesis_consumer import (
            KinesisShardConsumer, KinesisEFOConsumer
        )

        if self.use_efo and self._consumer_arn:
            consumer: Any = KinesisEFOConsumer(
                stream_name=self.stream_name,
                shard_id=shard_id,
                consumer_arn=self._consumer_arn,
                region=self.region,
            )
        else:
            consumer = KinesisShardConsumer(
                stream_name=self.stream_name,
                shard_id=shard_id,
                region=self.region,
            )

        self._consumers[shard_id] = consumer
        self._tasks[shard_id] = asyncio.create_task(
            consumer.run(), name=f'kinesis-{shard_id}'
        )
        logger.info('kinesis_manager: started consumer task for shard %s (efo=%s)',
                    shard_id, self.use_efo)

    async def _refresh_loop(self) -> None:
        """Periodically refresh the shard list to handle stream resharding."""
        while self._running:
            await asyncio.sleep(_SHARD_REFRESH_SECS)
            if self._running:
                await self._refresh_shards()

    def get_status(self) -> dict:
        return {
            'stream_name': self.stream_name,
            'region': self.region,
            'use_efo': self.use_efo,
            'consumer_arn': self._consumer_arn,
            'active_shards': list(self._tasks.keys()),
            'shard_count': len(self._tasks),
        }


# ---------------------------------------------------------------------------
# App-level lifecycle hooks
# ---------------------------------------------------------------------------

_global_manager: KinesisManager | None = None


async def start_kinesis_manager(app: Any = None) -> None:
    """Start the global Kinesis manager as background asyncio tasks."""
    global _global_manager
    _global_manager = KinesisManager()
    await _global_manager.start()


async def stop_kinesis_manager() -> None:
    global _global_manager
    if _global_manager:
        await _global_manager.stop()
        _global_manager = None


def get_manager() -> KinesisManager | None:
    return _global_manager
