"""
SQS Consumer (P0-A)
Async long-polling consumer that reads security events from an AWS SQS queue,
normalises them into EventV2 canonical envelopes, and pushes them to a Redis
ingest stream for downstream pipeline processing.

Usage (add to app lifespan deferred startup):
    from src.connectors.aws.sqs_consumer import SQSPoller, start_sqs_poller
    await start_sqs_poller(app)

Env vars:
    SQS_QUEUE_URL           — SQS queue URL (required to activate)
    SQS_REGION              — AWS region (default us-east-1)
    SQS_MAX_MESSAGES        — messages per poll cycle (1-10, default 10)
    SQS_WAIT_TIME_SECONDS   — long-poll wait (0-20, default 20)
    SQS_DLQ_URL             — dead-letter queue URL for terminal failures
    SQS_MAX_RETRIES         — retry attempts before DLQ (default 3)
    SQS_TENANT_ID           — tenant tag to attach to each event (default 'aws')
    REDIS_URL               — Redis for XADD (default redis://localhost:6379)
    REDIS_INGEST_STREAM     — stream key (default ingest_stream)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
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

_SQS_QUEUE_URL = os.getenv('SQS_QUEUE_URL', '')
_SQS_REGION = os.getenv('SQS_REGION', 'us-east-1')
_MAX_MESSAGES = max(1, min(10, int(os.getenv('SQS_MAX_MESSAGES', '10'))))
_WAIT_TIME = max(0, min(20, int(os.getenv('SQS_WAIT_TIME_SECONDS', '20'))))
_DLQ_URL = os.getenv('SQS_DLQ_URL', '')
_MAX_RETRIES = int(os.getenv('SQS_MAX_RETRIES', '3'))
_TENANT_ID = os.getenv('SQS_TENANT_ID', 'aws')
_REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379')
_INGEST_STREAM = os.getenv('REDIS_INGEST_STREAM', 'ingest_stream')


# ---------------------------------------------------------------------------
# Normaliser — translates SQS message bodies into EventV2 envelopes
# ---------------------------------------------------------------------------

def _normalise_guardduty(detail: dict) -> dict:
    finding = detail.get('detail', detail)
    return {
        'event_type': 'guardduty_finding',
        'severity': finding.get('severity', 0),
        'source_ip': (finding.get('service') or {}).get('action', {}).get(
            'networkConnectionAction', {}
        ).get('remoteIpDetails', {}).get('ipAddressV4'),
        'resource_type': finding.get('resource', {}).get('resourceType'),
        'title': finding.get('title'),
        'description': finding.get('description'),
        'region': finding.get('region'),
        'account_id': finding.get('accountId'),
        'raw': finding,
    }


def _normalise_securityhub(detail: dict) -> dict:
    finding = (detail.get('detail', {}).get('findings') or [detail])[0]
    return {
        'event_type': 'securityhub_finding',
        'severity': (finding.get('Severity') or {}).get('Normalized', 0),
        'title': finding.get('Title'),
        'description': finding.get('Description'),
        'resource_arns': [
            r.get('Id') for r in finding.get('Resources', [])
        ],
        'compliance': finding.get('Compliance', {}).get('Status'),
        'raw': finding,
    }


def _normalise_generic(body: dict) -> dict:
    return {
        'event_type': body.get('source') or body.get('type') or 'sqs_event',
        'raw': body,
    }


def normalise_sqs_message(body: dict) -> dict:
    """Convert a raw SQS message body into an EventV2 canonical envelope."""
    source = body.get('source', '')
    if 'guardduty' in source:
        payload = _normalise_guardduty(body)
    elif 'securityhub' in source:
        payload = _normalise_securityhub(body)
    else:
        payload = _normalise_generic(body)

    return {
        'v': 2,
        'event_id': str(uuid.uuid4()),
        'tenant_id': _TENANT_ID,
        'ingest_ts': time.time(),
        'connector': 'sqs',
        **payload,
    }


# ---------------------------------------------------------------------------
# Redis push helper
# ---------------------------------------------------------------------------

async def _push_to_redis(event_envelope: dict) -> bool:
    try:
        import redis.asyncio as aioredis  # type: ignore
        r = aioredis.from_url(_REDIS_URL, decode_responses=True)
        payload = json.dumps(event_envelope, default=str)
        await r.xadd(_INGEST_STREAM, {'data': payload})
        await r.aclose()
        return True
    except Exception as exc:
        logger.warning('sqs_consumer: redis push failed: %s', exc)
        return False


async def _send_to_dlq(sqs_client: Any, receipt_handle: str, body_str: str) -> None:
    """Forward a message to the dead-letter queue."""
    if not _DLQ_URL:
        return
    try:
        await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: sqs_client.send_message(QueueUrl=_DLQ_URL, MessageBody=body_str),
        )
    except Exception as exc:
        logger.error('sqs_consumer: DLQ send failed: %s', exc)


# ---------------------------------------------------------------------------
# Poller class
# ---------------------------------------------------------------------------

class SQSPoller:
    """Async SQS long-poll consumer with retry and DLQ support."""

    def __init__(
        self,
        queue_url: str = _SQS_QUEUE_URL,
        on_message: Callable[[dict], Awaitable[bool]] | None = None,
    ) -> None:
        self.queue_url = queue_url
        self.on_message = on_message or _push_to_redis
        self._running = False
        self._task: asyncio.Task | None = None

    @staticmethod
    def check_ready() -> tuple[bool, str]:
        """Return (ok, message) — call at startup to surface missing dependencies."""
        if not _BOTO3_AVAILABLE:
            return False, 'boto3 not installed; pip install boto3'
        if not _SQS_QUEUE_URL:
            return False, 'SQS_QUEUE_URL env var not set'
        return True, 'ok'

    async def start(self) -> None:
        if not self.queue_url:
            logger.info('sqs_consumer: SQS_QUEUE_URL not set — poller disabled')
            return
        if not _BOTO3_AVAILABLE:
            raise ImportError(
                'sqs_consumer: boto3 is required but not installed. '
                f'pip install boto3  (SQS_QUEUE_URL={self.queue_url!r} is configured)'
            )
        self._running = True
        self._task = asyncio.create_task(self._poll_loop())
        logger.info('sqs_consumer: started polling %s', self.queue_url)

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _poll_loop(self) -> None:
        client = _boto3.client('sqs', region_name=_SQS_REGION)
        loop = asyncio.get_event_loop()

        while self._running:
            try:
                response = await loop.run_in_executor(
                    None,
                    lambda: client.receive_message(
                        QueueUrl=self.queue_url,
                        MaxNumberOfMessages=_MAX_MESSAGES,
                        WaitTimeSeconds=_WAIT_TIME,
                        AttributeNames=['ApproximateReceiveCount'],
                    ),
                )
            except Exception as exc:
                logger.error('sqs_consumer: receive_message failed: %s', exc)
                await asyncio.sleep(5)
                continue

            messages = response.get('Messages', [])
            for msg in messages:
                receipt = msg['ReceiptHandle']
                body_str = msg.get('Body', '{}')
                receive_count = int(
                    msg.get('Attributes', {}).get('ApproximateReceiveCount', '0')
                )
                try:
                    body = json.loads(body_str)
                    # SNS-wrapped message
                    if 'Message' in body and isinstance(body['Message'], str):
                        body = json.loads(body['Message'])
                except Exception:
                    body = {'raw_body': body_str}

                envelope = normalise_sqs_message(body)

                if receive_count >= _MAX_RETRIES:
                    logger.warning(
                        'sqs_consumer: message exceeded max retries (%d), sending to DLQ', _MAX_RETRIES
                    )
                    await _send_to_dlq(client, receipt, body_str)
                    # Delete from main queue
                    await loop.run_in_executor(
                        None,
                        lambda r=receipt: client.delete_message(
                            QueueUrl=self.queue_url, ReceiptHandle=r
                        ),
                    )
                    continue

                success = await self.on_message(envelope)
                if success:
                    await loop.run_in_executor(
                        None,
                        lambda r=receipt: client.delete_message(
                            QueueUrl=self.queue_url, ReceiptHandle=r
                        ),
                    )
                else:
                    logger.warning(
                        'sqs_consumer: message processing failed — will retry (count=%d)', receive_count
                    )
                    # Leave message in queue for visibility-timeout retry

        logger.info('sqs_consumer: poll loop exited')


# ---------------------------------------------------------------------------
# App-level startup hook
# ---------------------------------------------------------------------------

_global_poller: SQSPoller | None = None


async def start_sqs_poller(app: Any = None) -> None:  # noqa: ANN001
    """Start the global SQS poller as a background asyncio task."""
    global _global_poller
    _global_poller = SQSPoller()
    await _global_poller.start()


async def stop_sqs_poller() -> None:
    global _global_poller
    if _global_poller:
        await _global_poller.stop()
        _global_poller = None
