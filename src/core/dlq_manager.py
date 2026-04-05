"""Dead-letter queue manager: retries failed decision persists.

This service polls the `decisions_dlq` table and attempts to re-deliver entries by
calling the upstream repository upsert API. On success it removes the DLQ row;
on failure it increments attempts and applies exponential backoff.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any, Dict, Optional
from core.metrics.registry import metric_gauge, metric_counter

_DLQ_GAUGE = metric_gauge('decisions', 'dlq_size', 'Number of rows in decisions_dlq')
_DLQ_FAILURES = metric_counter('decisions', 'dlq_failures', 'DLQ delivery failures')

logger = logging.getLogger(__name__)

# Emit DLQ debug logs only when DLQ_DEBUG=1 in env
DLQ_DEBUG = os.getenv('DLQ_DEBUG', '0') in {'1', 'true', 'yes'}

def _dlog(msg: str, *args, **kwargs) -> None:
    if DLQ_DEBUG:
        logger.debug(msg, *args, **kwargs)


class DLQManager:
    def __init__(self, poll_interval_s: int = 30, max_attempts: int = 5):
        self._interval = poll_interval_s
        self._max_attempts = max_attempts
        self._task = None
        self._stopping = False

    async def _fetch_dlq(self, limit: int = 50):
        try:
            from db.adapter import fetch as db_fetch
            # Only fetch rows that are due: next_retry is null or <= CURRENT_TIMESTAMP (works for Postgres and sqlite)
            rows = await db_fetch("SELECT id, event_id, payload, error, attempts, next_retry FROM decisions_dlq WHERE (next_retry IS NULL OR next_retry <= CURRENT_TIMESTAMP) ORDER BY COALESCE(next_retry, last_attempt) ASC LIMIT $1", limit)
            return rows or []
        except Exception:
            logger.debug('DLQ fetch failed', exc_info=True)
            return []

    async def _delete_dlq(self, dlq_id: int):
        try:
            from db.adapter import execute as db_execute
            await db_execute('DELETE FROM decisions_dlq WHERE id=$1', dlq_id)
        except Exception:
            logger.debug('Failed to delete DLQ row %s', dlq_id, exc_info=True)

    async def _update_dlq_attempt(self, dlq_id: int, attempts: int):
        try:
            from db.adapter import execute as db_execute
            # Use CURRENT_TIMESTAMP for broader compatibility (sqlite/Postgres)
            await db_execute('UPDATE decisions_dlq SET attempts=$1, last_attempt=CURRENT_TIMESTAMP WHERE id=$2', attempts, dlq_id)
        except Exception:
            logger.debug('Failed to update DLQ attempts for %s', dlq_id, exc_info=True)

    async def _attempt_redeliver(self, row: Dict[str, Any]):
        dlq_id = row.get('id')
        payload = row.get('payload') or {}
        # payload may be stored as a JSON string in sqlite fallback; coerce to dict
        try:
            if isinstance(payload, str):
                import json as _json
                payload = _json.loads(payload)
        except Exception:
            # leave as-is if parsing fails
            pass
        attempts = int(row.get('attempts') or 0)
        try:
            _dlog('DLQ redeliver start id=%s event_id=%s attempts=%s', dlq_id, row.get('event_id'), attempts)
            # Try to use upstream repo upsert if available
            try:
                import repositories.decisions_repo as dr
                upsert = getattr(dr, 'upsert_decision', None)
            except Exception:
                dr = None
                upsert = None
            if upsert:
                _dlog('Found upstream upsert_decision in repositories.decisions_repo; attempting upsert for event_id=%s', payload.get('event_id'))
                # construct minimal object expected by upsert_decision
                class _D:
                    pass
                d = _D()
                d.factors = payload.get('factors', [])
                d.verdict = payload.get('verdict')
                d.confidence = float(payload.get('confidence') or 0.0)
                d.processing_time_ms = float(payload.get('processing_time_ms') or 0.0)
                d.stage_timings = payload.get('stage_timings') or {}
                d.custody_hash = payload.get('custody_hash')
                tenant_id = payload.get('tenant_id')
                if asyncio.iscoroutinefunction(upsert):
                    await upsert(payload.get('event_id'), d, tenant_id)
                else:
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(None, upsert, payload.get('event_id'), d, tenant_id)
                    # success -> delete dlq row
                    _dlog('Upsert succeeded for event_id=%s; deleting dlq id=%s', payload.get('event_id'), dlq_id)
                    await self._delete_dlq(dlq_id)
                    return True
            # fallback: use repo_impl.persist if available
            try:
                from repositories.decisions_repo_impl import repo_impl
                if hasattr(repo_impl, 'persist'):
                    _dlog('Using repo_impl.persist fallback for dlq id=%s', dlq_id)
                    await repo_impl.persist(payload)
                    _dlog('repo_impl.persist succeeded; deleting dlq id=%s', dlq_id)
                    await self._delete_dlq(dlq_id)
                    return True
            except Exception:
                pass
            # if no repo path, re-use db insert semantics: attempt to insert into decisions table
            try:
                from db import database as _db
                execute = getattr(_db, 'execute', None) or getattr(_db, 'run', None)
                if execute:
                    sql = 'INSERT INTO decisions (event_id, verdict, confidence, processing_ms, factors, stage_timings, custody_hash, tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)'
                    if asyncio.iscoroutinefunction(execute):
                        await execute(sql, payload.get('event_id'), payload.get('verdict'), float(payload.get('confidence') or 0.0), float(payload.get('processing_time_ms') or 0.0), payload.get('factors'), payload.get('stage_timings'), payload.get('custody_hash'), payload.get('tenant_id'))
                    else:
                        loop = asyncio.get_event_loop()
                        await loop.run_in_executor(None, execute, sql, payload.get('event_id'), payload.get('verdict'), float(payload.get('confidence') or 0.0), float(payload.get('processing_time_ms') or 0.0), payload.get('factors'), payload.get('stage_timings'), payload.get('custody_hash'), payload.get('tenant_id'))
                    _dlog('Inserted into decisions table fallback; deleting dlq id=%s', dlq_id)
                    await self._delete_dlq(dlq_id)
                    return True
            except Exception:
                _dlog('decisions table fallback failed for dlq id=%s', dlq_id)
                pass
        except Exception as exc:
            _dlog('Redeliver attempt failed for dlq id %s: %s', dlq_id, exc)

        # update attempts and possibly leave for future retries
        attempts += 1
        # when reaching max attempts, alert and leave for manual review
        if attempts >= self._max_attempts:
            logger.warning('DLQ entry %s reached max attempts (%s); alerting', dlq_id, attempts)
            try:
                from core.alerts import alert_dlq_max_attempts
                await alert_dlq_max_attempts(row)
            except Exception:
                logger.debug('Failed to send DLQ alert')
            _dlog('Marking dlq id=%s attempts=%s (max reached)', dlq_id, attempts)
            await self._update_dlq_attempt(dlq_id, attempts)
            return False
        # update attempt and backoff
        _dlog('Updating dlq id=%s attempts=%s and leaving for retry', dlq_id, attempts)
        await self._update_dlq_attempt(dlq_id, attempts)
        return False

    async def _run_loop(self):
        logger.info('DLQManager started; interval=%s', self._interval)
        while not self._stopping:
            try:
                    rows = await self._fetch_dlq(limit=50)
                    try:
                        _DLQ_GAUGE.set(len(rows) if rows is not None else 0)
                    except Exception:
                        pass
                    for r in rows:
                        try:
                            ok = await self._attempt_redeliver(r)
                            if not ok:
                                try:
                                    _DLQ_FAILURES.inc()
                                except Exception:
                                    pass
                        except Exception:
                            logger.debug('Failed attempt for DLQ row', exc_info=True)
            except Exception:
                logger.exception('DLQ loop encountered an error')
            await asyncio.sleep(self._interval)
        logger.info('DLQManager stopped')

    def start(self):
        if self._task:
            return
        loop = asyncio.get_event_loop()
        self._task = loop.create_task(self._run_loop())

    async def stop(self):
        self._stopping = True
        if self._task:
            await self._task
