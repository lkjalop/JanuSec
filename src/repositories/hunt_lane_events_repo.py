"""Repository for persisting hunt lane emissions"""
from __future__ import annotations

import logging
import os
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional

logger = logging.getLogger(__name__)

_FALLBACK_MAX = max(1, int(os.getenv('HUNT_LANE_FALLBACK_MAX', '512')))
_INMEM_BUFFER: Deque[Dict[str, Any]] = deque(maxlen=_FALLBACK_MAX)


def _push_fallback(entry: Dict[str, Any]) -> None:
    _INMEM_BUFFER.appendleft(entry)


def _fallback_rows(tenant_id: Optional[str], lane: Optional[str], limit: int) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for item in _INMEM_BUFFER:
        if tenant_id and item.get('tenant_id') != tenant_id:
            continue
        if lane and item.get('lane') != lane:
            continue
        results.append(dict(item))
        if len(results) >= limit:
            break
    return results


class HuntLaneEventsRepository:
    """Persist hunt lane emissions with optional in-memory fallback for tests."""

    def __init__(self, pool: Any | None, *, fallback_enabled: Optional[bool] = None) -> None:
        self.pool = pool
        self.require_tenant = True
        if fallback_enabled is None:
            fallback_enabled = os.getenv('HUNT_LANE_INMEM_FALLBACK', '1').lower() not in {'0', 'false', 'no'}
        self._fallback_enabled = bool(fallback_enabled)

    @staticmethod
    def _has_acquire(pool: Any | None) -> bool:
        return pool is not None and hasattr(pool, 'acquire')

    @classmethod
    def reset_fallback(cls) -> None:
        _INMEM_BUFFER.clear()

    async def record(
        self,
        tenant_id: Optional[str],
        event_id: str,
        lane: str,
        factors: List[str],
        latency_ms: float,
    ) -> Dict[str, Any]:
        if self.require_tenant and not tenant_id:
            raise ValueError('tenant_id required for hunt lane persistence')

        entry = {
            'created_at': time.time(),
            'tenant_id': tenant_id,
            'event_id': event_id,
            'lane': lane,
            'factors': list(factors),
            'latency_ms': float(latency_ms),
        }

        if self._has_acquire(self.pool):
            try:
                async with self.pool.acquire() as conn:  # type: ignore[union-attr]
                    await conn.execute(
                        "INSERT INTO hunt_lane_events (tenant_id, event_id, lane, factors, latency_ms) VALUES ($1,$2,$3,$4,$5)",
                        tenant_id,
                        event_id,
                        lane,
                        factors,
                        latency_ms,
                    )
            except Exception as exc:
                if self._fallback_enabled:
                    logger.warning('Failed to record hunt lane event, using in-memory store: %s', exc)
                    _push_fallback(entry)
                else:
                    raise
            else:
                if self._fallback_enabled:
                    _push_fallback(entry)
            return entry

        if self._fallback_enabled:
            _push_fallback(entry)
            return entry

        raise RuntimeError('HuntLaneEventsRepository pool unavailable and fallback disabled')

    async def recent(
        self,
        tenant_id: Optional[str],
        lane: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        if self.require_tenant and not tenant_id:
            raise ValueError('tenant_id required for recent hunt lane events')

        limit = max(1, min(limit, _FALLBACK_MAX))

        if self._has_acquire(self.pool):
            clauses: List[str] = []
            params: List[Any] = []
            idx = 1
            if tenant_id:
                clauses.append(f"tenant_id=${idx}")
                params.append(tenant_id)
                idx += 1
            if lane:
                clauses.append(f"lane=${idx}")
                params.append(lane)
                idx += 1
            where = f"WHERE {' AND '.join(clauses)}" if clauses else ''
            query = (
                f"SELECT created_at, tenant_id, event_id, lane, factors, latency_ms "
                f"FROM hunt_lane_events {where} ORDER BY created_at DESC LIMIT ${idx}"
            )
            params.append(limit)
            try:
                async with self.pool.acquire() as conn:  # type: ignore[union-attr]
                    rows = await conn.fetch(query, *params)
                return [dict(r) for r in rows]
            except Exception as exc:
                if not self._fallback_enabled:
                    raise
                logger.warning('Falling back to in-memory hunt lane events query: %s', exc)

        if self._fallback_enabled:
            return _fallback_rows(tenant_id, lane, limit)

        return []


__all__ = ['HuntLaneEventsRepository']
