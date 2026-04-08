"""
EventBridge HTTPS Webhook Endpoint (P1)
FastAPI router that acts as an AWS EventBridge HTTPS target.  EventBridge
supports sending events directly to HTTPS endpoints (no SQS required), which is
simpler for accounts that already have VPC private links or prefer not to manage
SQS queues.

How it works:
  1. AWS EventBridge rule is configured with an HTTPS target pointing at
     POST /api/v1/ingest/eventbridge
  2. EventBridge signs each request with its connection auth token
  3. This endpoint verifies the token, normalises the event body, and pushes
     to Redis ingest_stream

Key differences from SQS path:
  - Push vs pull → sub-second latency vs SQS long-poll (~200ms)
  - No SQS queue to manage
  - Requires public HTTPS endpoint (or VPC API Gateway → private link)

Env vars:
    EB_WEBHOOK_TOKEN        — shared secret to validate EventBridge auth header
                              (should match the ApiDestination connection's auth token)
    EB_WEBHOOK_HEADER       — header name for the token (default 'Authorization')
    EB_STRICT_AUTH          — '0' to disable auth check (dev only, default '1')
    KINESIS_TENANT_ID       — tenant for events (default 'aws')
    REDIS_URL               — Redis ingest_stream target
    REDIS_INGEST_STREAM     — stream key (default 'ingest_stream')
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
import uuid

from fastapi import APIRouter, HTTPException, Request, Response

logger = logging.getLogger(__name__)

router = APIRouter(prefix='/api/v1/ingest', tags=['ingest'])

_EB_TOKEN = os.getenv('EB_WEBHOOK_TOKEN', '')
_EB_HEADER = os.getenv('EB_WEBHOOK_HEADER', 'Authorization')
_STRICT_AUTH = os.getenv('EB_STRICT_AUTH', '1') not in ('0', 'false', 'no')
_TENANT_ID = os.getenv('KINESIS_TENANT_ID', os.getenv('SQS_TENANT_ID', 'aws'))
_REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379')
_INGEST_STREAM = os.getenv('REDIS_INGEST_STREAM', 'ingest_stream')


def _verify_token(request: Request) -> bool:
    """Verify the EventBridge auth token from the configured header."""
    if not _STRICT_AUTH:
        return True
    if not _EB_TOKEN:
        logger.warning('ingest_eventbridge: EB_WEBHOOK_TOKEN not set but STRICT_AUTH=1')
        return False
    token_value = request.headers.get(_EB_HEADER, '')
    # Support both raw token and "Bearer <token>" formats
    if token_value.lower().startswith('bearer '):
        token_value = token_value[7:]
    # Timing-safe comparison
    expected = _EB_TOKEN.encode('utf-8')
    received = token_value.encode('utf-8')
    if len(expected) != len(received):
        return False
    return hmac.compare_digest(expected, received)


def _normalise_eb_event(body: dict) -> dict:
    """Convert an EventBridge event envelope to an EventV2 canonical format."""
    detail = body.get('detail') or {}
    source = body.get('source', 'aws.unknown')
    event_type = body.get('detail-type', 'eventbridge_event')
    ts = body.get('time') or time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

    # Detect specific AWS service events and enrich accordingly
    if 'guardduty' in source:
        normalised_type = 'guardduty_finding'
        severity = detail.get('severity', 0)
    elif 'securityhub' in source:
        normalised_type = 'securityhub_finding'
        severity = (detail.get('Severity') or {}).get('Normalized', 0) / 100
    elif 'cloudtrail' in source:
        normalised_type = 'cloudtrail_event'
        severity = 0.3  # enriched by pipeline
    elif 'config' in source:
        normalised_type = 'config_compliance_change'
        severity = 0.5
    elif 'macie' in source:
        normalised_type = 'macie_finding'
        severity = 0.7
    else:
        normalised_type = 'eventbridge_event'
        severity = 0.0

    return {
        'v': 2,
        'event_id': str(uuid.uuid4()),
        'tenant_id': _TENANT_ID,
        'ingest_ts': time.time(),
        'valid_time_start': ts,
        'tx_time_start': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'connector': 'eventbridge_webhook',
        'source': source,
        'event_type': normalised_type,
        'severity': severity,
        'detail_type': event_type,
        'account': body.get('account'),
        'region': body.get('region'),
        'raw': body,
    }


async def _push_to_redis(envelope: dict) -> bool:
    try:
        import redis.asyncio as aioredis  # type: ignore
        r = aioredis.from_url(_REDIS_URL, decode_responses=True)
        await r.xadd(_INGEST_STREAM, {'data': json.dumps(envelope, default=str)})
        await r.aclose()
        return True
    except Exception as exc:
        logger.warning('ingest_eventbridge: redis push failed: %s', exc)
        return False


@router.post('/eventbridge')
async def receive_eventbridge_event(request: Request) -> Response:
    """HTTPS target endpoint for AWS EventBridge ApiDestination."""
    # Auth check
    if _STRICT_AUTH and not _verify_token(request):
        raise HTTPException(status_code=401, detail='invalid_token')

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail='invalid_json')

    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail='expected_object')

    # EventBridge can send arrays of events when batching is enabled
    if isinstance(body, list):
        events = body
    elif 'detail' in body or 'source' in body:
        events = [body]
    else:
        # Possible SNS/EventBridge batch wrapper
        events = body.get('Records', [body])

    pushed = 0
    errors = 0
    for event in events:
        try:
            envelope = _normalise_eb_event(event if isinstance(event, dict) else {'raw': event})
            if await _push_to_redis(envelope):
                pushed += 1
            else:
                errors += 1
        except Exception as exc:
            logger.error('ingest_eventbridge: processing error: %s', exc)
            errors += 1

    logger.info('ingest_eventbridge: pushed=%d errors=%d', pushed, errors)
    return Response(
        content=json.dumps({'pushed': pushed, 'errors': errors}),
        media_type='application/json',
        status_code=200 if errors == 0 else 207,
    )


@router.get('/eventbridge/health')
async def eventbridge_health() -> dict:
    """Health probe for the EventBridge webhook endpoint (used by EventBridge connection health checks)."""
    return {
        'status': 'ok',
        'connector': 'eventbridge_webhook',
        'strict_auth': _STRICT_AUTH,
        'tenant': _TENANT_ID,
        'ingest_stream': _INGEST_STREAM,
    }
