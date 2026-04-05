"""Concrete decisions repo implementation that delegates to repositories.decisions_repo.

Provides async persist(event_dict) and async list_recent(limit, tenant_id) used by the server.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
import asyncio

logger = logging.getLogger(__name__)


class DecisionsRepoImpl:
    def __init__(self, max_retries: int = 3, retry_backoff_s: float = 0.5):
        try:
            import repositories.decisions_repo as dr
            self._dr = dr
        except Exception:
            self._dr = None
        self.max_retries = max_retries
        self.retry_backoff_s = retry_backoff_s

    async def persist(self, decision: Dict[str, Any]) -> None:
        """Persist a decision dict using repositories.decisions_repo.upsert_decision with retries.

        Constructs the minimal expected object and calls into the upstream repo.
        """
        if not self._dr or not hasattr(self._dr, 'upsert_decision'):
            raise RuntimeError('decisions_repo backend not available')

        class _D:
            pass

        d = _D()
        d.factors = decision.get('factors', [])
        d.verdict = decision.get('verdict')
        d.confidence = float(decision.get('confidence') or 0.0)
        d.processing_time_ms = float(decision.get('processing_time_ms') or 0.0)
        d.stage_timings = decision.get('stage_timings') or {}
        d.custody_hash = decision.get('custody_hash') if 'custody_hash' in decision else None
        tenant_id = decision.get('tenant_id')

        last_exc = None
        for attempt in range(1, self.max_retries + 1):
            try:
                upsert = getattr(self._dr, 'upsert_decision')
                if asyncio.iscoroutinefunction(upsert):
                    await upsert(decision.get('event_id'), d, tenant_id)
                else:
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(None, upsert, decision.get('event_id'), d, tenant_id)
                return
            except Exception as exc:
                last_exc = exc
                logger.warning('persist attempt %d failed: %s', attempt, exc)
                if attempt < self.max_retries:
                    await asyncio.sleep(self.retry_backoff_s * attempt)
        logger.exception('All persist attempts failed')
        # Attempt to write to DLQ table if available to avoid data loss
        try:
            dlq_fn = getattr(self._dr, 'write_dlq', None)
            payload = decision
            err_text = str(last_exc)
            if dlq_fn:
                if asyncio.iscoroutinefunction(dlq_fn):
                    await dlq_fn(payload, err_text)
                else:
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(None, dlq_fn, payload, err_text)
                return
            # Fallback: use our DB adapter helpers for DLQ insert
            try:
                from db.adapter import execute as db_execute
                sql = "INSERT INTO decisions_dlq (event_id, payload, error, attempts, last_attempt) VALUES ($1, $2, $3, $4, NOW())"
                await db_execute(sql, payload.get('event_id'), payload, err_text, 0)
                return
            except Exception:
                logger.debug('DLQ fallback write failed', exc_info=True)
        except Exception:
            logger.exception('Failed to write to DLQ')
        # Finally surface the original error
        raise last_exc
    async def ensure_schema(self):
        """If the upstream repo exposes run_migrations, call it to ensure schema."""
        if not self._dr:
            return
        run_mig = getattr(self._dr, 'run_migrations', None)
        if not run_mig:
            logger.debug('upstream repo has no run_migrations')
            return
        if asyncio.iscoroutinefunction(run_mig):
            await run_mig()
        else:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, run_mig)


repo_impl = DecisionsRepoImpl()
