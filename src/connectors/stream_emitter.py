"""Shared helper: emit connector rows to the streaming ingest API.

Usage (sync callers like Okta/EntraID):
    from src.connectors.stream_emitter import emit_to_stream_sync
    emit_to_stream_sync(rows, source='okta')

Usage (async callers like SailPoint, Proofpoint, Mimecast):
    from src.connectors.stream_emitter import emit_to_stream
    await emit_to_stream(rows, source='mimecast')

Config (environment variables):
    JANUSEC_STREAMING_MODE      — set to "true" to activate
    JANUSEC_STREAM_ASSESSMENT_ID — streaming session ID (required when mode is on)
    JANUSEC_API_BASE_URL        — base URL for internal API (default: http://localhost:8080)
    API_KEY / JANUSEC_API_KEY   — API key for auth
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

_BATCH_SIZE = 500  # rows per POST call


def _stream_cfg() -> tuple[bool, str, str, str]:
    """Return (active, assessment_id, base_url, api_key)."""
    active = os.getenv('JANUSEC_STREAMING_MODE', '').lower() in ('1', 'true', 'yes')
    assessment_id = os.getenv('JANUSEC_STREAM_ASSESSMENT_ID', '')
    base_url = (os.getenv('JANUSEC_API_BASE_URL') or os.getenv('API_BASE_URL') or 'http://localhost:8080').rstrip('/')
    api_key = os.getenv('JANUSEC_API_KEY') or os.getenv('API_KEY') or 'devkey123'
    return active, assessment_id, base_url, api_key


def is_streaming_active() -> bool:
    active, aid, _, _ = _stream_cfg()
    return active and bool(aid)


async def emit_to_stream(
    rows: List[Dict[str, Any]],
    source: str,
    *,
    assessment_id: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
) -> Dict[str, Any]:
    """Async: POST rows to /api/v1/stream/sessions/{id}/ingest in _BATCH_SIZE chunks."""
    if not rows:
        return {'accepted': 0, 'batches': 0}

    cfg_active, cfg_aid, cfg_base, cfg_key = _stream_cfg()
    aid = assessment_id or cfg_aid
    base = (base_url or cfg_base).rstrip('/')
    key = api_key or cfg_key

    if not aid:
        logger.warning('emit_to_stream: no assessment_id configured; dropping %d rows', len(rows))
        return {'accepted': 0, 'batches': 0}

    try:
        import httpx as _httpx
    except ImportError:
        logger.error('emit_to_stream: httpx not installed; cannot emit %d rows', len(rows))
        return {'accepted': 0, 'batches': 0}

    url = f'{base}/api/v1/stream/sessions/{aid}/ingest'
    headers = {'X-API-Key': key, 'Content-Type': 'application/json'}
    total_accepted = 0
    batches_sent = 0

    async with _httpx.AsyncClient(timeout=30) as client:
        for i in range(0, len(rows), _BATCH_SIZE):
            batch = rows[i:i + _BATCH_SIZE]
            try:
                resp = await client.post(url, headers=headers, json={'rows': batch, 'source': source})
                resp.raise_for_status()
                data = resp.json()
                total_accepted += data.get('accepted', len(batch))
                batches_sent += 1
            except Exception as exc:
                logger.warning('emit_to_stream batch %d failed: %s', batches_sent, exc)

    logger.debug('emit_to_stream: %s → %d rows in %d batches to session %s', source, total_accepted, batches_sent, aid)
    return {'accepted': total_accepted, 'batches': batches_sent}


def emit_to_stream_sync(
    rows: List[Dict[str, Any]],
    source: str,
    *,
    assessment_id: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
) -> Dict[str, Any]:
    """Sync wrapper for connectors running outside an event loop (Okta, EntraID)."""
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                fut = ex.submit(
                    asyncio.run,
                    emit_to_stream(rows, source, assessment_id=assessment_id, base_url=base_url, api_key=api_key),
                )
                return fut.result(timeout=60)
        else:
            return loop.run_until_complete(
                emit_to_stream(rows, source, assessment_id=assessment_id, base_url=base_url, api_key=api_key)
            )
    except Exception as exc:
        logger.warning('emit_to_stream_sync error: %s', exc)
        return {'accepted': 0, 'batches': 0}


__all__ = ['is_streaming_active', 'emit_to_stream', 'emit_to_stream_sync']
