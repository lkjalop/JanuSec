from __future__ import annotations

"""Proofpoint TAP collector (skeleton).

Polls TAP SIEM endpoints for message logs and normalizes minimal fields to
forward into the email ingest API. Cursor persisted via TenantStore.
"""

import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional, AsyncIterator

try:
    from prometheus_client import Counter, Gauge
    _PROM = True
except Exception:
    _PROM = False

import asyncio

from src.integrations.tenant_store import TenantStore
from src.integrations._backoff import retry_with_backoff
try:
    # Reuse safe counter to avoid duplicate registration
    from src.api.metrics_init import _safe_counter  # type: ignore
except Exception:
    _safe_counter = None  # type: ignore

logger = logging.getLogger(__name__)

if _PROM:
    TAP_POLL_SUCCESS = Counter('proofpoint_tap_poll_success_total', 'Proofpoint TAP successful poll calls')
    TAP_POLL_ERRORS = Counter('proofpoint_tap_poll_error_total', 'Proofpoint TAP poll errors')
    TAP_LAST_SUCCESS = Gauge('proofpoint_tap_last_success_timestamp', 'Last successful TAP poll timestamp')
    TAP_RATE_LIMIT_HITS = Counter('proofpoint_tap_rate_limit_hits_total', 'Proofpoint TAP rate-limited requests')
    TAP_HTTP_429 = Counter('proofpoint_tap_http_429_total', 'Proofpoint TAP HTTP 429 responses')
    TAP_INGEST_HTTP_429 = Counter('proofpoint_tap_ingest_http_429_total', 'Proofpoint TAP ingest HTTP 429 responses')
    _tap_ingest_rate_drops = None
    try:
        if _safe_counter is not None:
            _tap_ingest_rate_drops = _safe_counter('ingest_rate_drops_total','Ingest rate-limited drops',['tenant_id','source'])
    except Exception:
        _tap_ingest_rate_drops = None


class ProofpointTAPCollector:
    BASE = os.getenv('PROOFPOINT_TAP_BASE', 'https://tap-api.proofpoint.com')
    POLL_INTERVAL = int(os.getenv('PROOFPOINT_TAP_POLL_INTERVAL', '300'))

    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id
        self._store = TenantStore()
        self._since_iso: Optional[str] = self._store.load_cursor(tenant_id, 'proofpoint', 'sinceTime')
        self._user = os.getenv('PROOFPOINT_TAP_USER')
        self._secret = os.getenv('PROOFPOINT_TAP_SECRET')
        # Optional rate limiter
        try:
            from aiolimiter import AsyncLimiter  # type: ignore
            rate = int(os.getenv('PROOFPOINT_TAP_RATE_PER_SEC','60'))
            self._rate_limiter = AsyncLimiter(max_rate=rate, time_period=1)
        except Exception:
            self._rate_limiter = None

    def _default_since(self) -> str:
        dt = datetime.now(timezone.utc) - timedelta(hours=1)
        return dt.isoformat()

    async def start_polling(self) -> AsyncIterator[Dict[str, Any]]:
        while True:
            try:
                async for evt in self._poll_once():
                    yield evt
            except Exception:
                logger.exception('TAP polling error')
                await asyncio.sleep(60)
            await asyncio.sleep(self.POLL_INTERVAL)

    async def _poll_once(self) -> AsyncIterator[Dict[str, Any]]:
        since = self._since_iso or self._default_since()
        url = f"{self.BASE.rstrip('/')}/v2/siem/messages?sinceTime={since}"
        auth = (self._user or '', self._secret or '')
        try:
            import httpx
            if self._rate_limiter is not None:
                async with self._rate_limiter:
                    if _PROM:
                        TAP_RATE_LIMIT_HITS.inc()
                    def _call():
                        with httpx.Client(timeout=60.0) as c:
                            return c.get(url, auth=auth)
                    resp = await asyncio.to_thread(retry_with_backoff, _call)
            else:
                def _call():
                    with httpx.Client(timeout=60.0) as c:
                        return c.get(url, auth=auth)
                resp = await asyncio.to_thread(retry_with_backoff, _call)
            # Pre-check for 429 to increment dedicated metric
            if _PROM and resp.status_code == 429:
                TAP_HTTP_429.inc()
            resp.raise_for_status()
            data = resp.json()
            # messages array; update cursor to now on success
            msgs = data.get('messages', []) if isinstance(data, dict) else []
            for m in msgs:
                ev = self._normalize_message(m)
                if ev:
                    yield ev
            self._since_iso = datetime.now(timezone.utc).isoformat()
            try:
                self._store.save_cursor(self.tenant_id, 'proofpoint', 'sinceTime', self._since_iso)
            except Exception:
                pass
            if _PROM:
                TAP_POLL_SUCCESS.inc()
                TAP_LAST_SUCCESS.set_to_current_time()
        except Exception:
            if _PROM:
                TAP_POLL_ERRORS.inc()
            logger.exception('TAP API error')

    def _normalize_message(self, m: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            # Minimal ingestion payload for /api/v1/email/ingest
            frm = (m.get('fromAddress') or '').strip()
            to_list = m.get('toAddresses') or []
            to_addr = to_list[0] if to_list else ''
            subject = m.get('subject') or ''
            auth_res = m.get('authenticationResults') or ''
            return {
                'from': frm,
                'to': to_addr,
                'subject': subject,
                'raw': {
                    'authentication_results': auth_res,
                    'tap': {
                        'threatsInfoMap': m.get('threatsInfoMap'),
                        'messageID': m.get('messageID'),
                        'messageTime': m.get('messageTime'),
                    }
                }
            }
        except Exception:
            return None

    async def forward_to_ingest(self, events: List[Dict[str, Any]]) -> int:
        if not events:
            return 0
        try:
            import httpx
            base = os.getenv('API_BASE_URL', 'http://localhost:8080')
            api_key = os.getenv('API_KEY')
            url = f"{base.rstrip('/')}/api/v1/email/ingest"
            headers = {'x-api-key': api_key, 'Content-Type': 'application/json'}
            sent = 0
            # Configurable batch size and per-event concurrency caps
            try:
                batch_size = int(os.getenv('PROOFPOINT_INGEST_BATCH_SIZE', os.getenv('EMAIL_INGEST_BATCH_SIZE','200')) or 200)
            except Exception:
                batch_size = 200
            try:
                per_event_conc = int(os.getenv('PROOFPOINT_INGEST_CONCURRENCY', os.getenv('EMAIL_INGEST_CONCURRENCY','8')) or 8)
            except Exception:
                per_event_conc = 8
            chunks: List[List[Dict[str, Any]]] = [events[i:i+batch_size] for i in range(0, len(events), batch_size)]
            async with httpx.AsyncClient(timeout=30) as client:
                # Iterate chunks; attempt batch first then fallback
                url_batch = f"{base.rstrip('/')}/api/v1/email/ingest/batch"
                for chunk in chunks:
                    try:
                        rb = await client.post(url_batch, headers=headers, json={'events': chunk})
                        if _PROM and rb.status_code == 429:
                            TAP_INGEST_HTTP_429.inc()
                            try:
                                if _tap_ingest_rate_drops is not None:
                                    _tap_ingest_rate_drops.labels(self.tenant_id, 'proofpoint').inc()  # type: ignore
                            except Exception:
                                pass
                            try:
                                await asyncio.sleep(1.0)
                            except Exception:
                                pass
                            raise RuntimeError('batch_rate_limited')
                        if rb.status_code == 404:
                            raise RuntimeError('batch_not_supported')
                        rb.raise_for_status()
                        sent += len(chunk)
                        continue
                    except Exception:
                        # Fallback to per-event with bounded concurrency
                        sem = asyncio.Semaphore(max(1, per_event_conc))
                        async def _send(ev: Dict[str, Any]) -> int:
                            async with sem:
                                r = await client.post(url, headers=headers, json=ev)
                                if _PROM and r.status_code == 429:
                                    TAP_INGEST_HTTP_429.inc()
                                    try:
                                        if _tap_ingest_rate_drops is not None:
                                            _tap_ingest_rate_drops.labels(self.tenant_id, 'proofpoint').inc()  # type: ignore
                                    except Exception:
                                        pass
                                    await asyncio.sleep(0.25)
                                    return 0
                                r.raise_for_status()
                                return 1
                        results = await asyncio.gather(*[_send(ev) for ev in chunk], return_exceptions=True)
                        for res in results:
                            if isinstance(res, int):
                                sent += res
            return sent
        except Exception:
            logger.exception('forward_to_ingest failed')
            return 0

    async def start_forwarder(self) -> None:
        """Simple forwarder loop: poll once and forward normalized events."""
        evs: List[Dict[str, Any]] = []
        async for ev in self._poll_once():
            evs.append(ev)
        if evs:
            await self.forward_to_ingest(evs)

    def health_snapshot(self) -> Dict[str, Any]:
        return {
            'last_since_iso': self._since_iso,
            'tenant': self.tenant_id,
            'rate_limiter': bool(self._rate_limiter),
        }


__all__ = ['ProofpointTAPCollector']
