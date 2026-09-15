"""Persistent DB-backed learner service.

This service reads/writes the `learned_weights` table and exposes simple nudging
logic. It uses the repo interface where possible, but will use the `db.database`
adapter to execute SQL when available.
"""
from __future__ import annotations

import asyncio
import time
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class PersistentLearnerService:
    def __init__(self, repo, interval_s: int = 60, model_version: str = 'v1'):
        self._repo = repo
        self._interval = interval_s
        self._task = None
        self._stopping = False
        self._model_version = model_version
        self._weights: Dict[str, float] = {}

    async def _load_weights(self):
        try:
            from db import database as _db
            fetch = getattr(_db, 'fetch', None) or getattr(_db, 'query', None)
            if fetch is None:
                return
            if asyncio.iscoroutinefunction(fetch):
                rows = await fetch('SELECT factor, weight FROM learned_weights WHERE model_version=$1', self._model_version)
            else:
                loop = asyncio.get_event_loop()
                rows = await loop.run_in_executor(None, fetch, 'SELECT factor, weight FROM learned_weights WHERE model_version=%s', self._model_version)
            for r in rows:
                self._weights[r.get('factor')] = float(r.get('weight'))
        except Exception:
            logger.debug('Failed to load learned weights; starting fresh')

    async def _upsert_weight(self, factor: str, weight: float):
        try:
            from db import database as _db
            execute = getattr(_db, 'execute', None) or getattr(_db, 'run', None)
            if execute is None:
                return
            sql = 'INSERT INTO learned_weights (factor, weight, model_version, created_at, updated_at) VALUES ($1,$2,$3,NOW(),NOW()) ON CONFLICT (factor, model_version) DO UPDATE SET weight = $2, updated_at = NOW()'
            if asyncio.iscoroutinefunction(execute):
                await execute(sql, factor, float(weight), self._model_version)
            else:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, execute, sql, factor, float(weight), self._model_version)
        except Exception:
            logger.exception('Failed to persist learned weight for %s', factor)

    async def _scan_and_nudge(self, batch_size: int = 500):
        try:
            decisions = await self._repo.list_recent(limit=batch_size)
        except Exception as exc:
            logger.debug('Learner: failed to fetch recent decisions: %s', exc)
            return
        for dec in decisions:
            confidence = float(dec.get('confidence') or 0.0)
            verdict = (dec.get('verdict') or '').lower()
            if not dec.get('factors'):
                continue
            for f in dec.get('factors', []):
                if isinstance(f, dict):
                    name = f.get('name') or f.get('factor')
                else:
                    name = str(f)
                if not name:
                    continue
                cur = self._weights.get(name, 0.0)
                old = cur
                if verdict == 'malicious' or confidence > 0.8:
                    cur += 0.02 * (confidence or 0.5)
                else:
                    decay = float(__import__('os').environ.get('LEARNER_DECAY', '0.995') or 0.995)
                    cur *= decay
                # Guardrail: clamp delta per-update to avoid runaway adjustments
                try:
                    max_delta = float(__import__('os').environ.get('MAX_WEIGHT_DELTA', '0.1') or 0.1)
                except Exception:
                    max_delta = 0.1
                delta = cur - old
                if abs(delta) > max_delta:
                    # If MIN_SAMPLE_FOR_ADJUST is configured, require enough labeled samples
                    try:
                        min_samples = int(__import__('os').environ.get('MIN_SAMPLE_FOR_ADJUST', '0') or 0)
                    except Exception:
                        min_samples = 0
                    allow = False
                    if min_samples <= 0:
                        allow = True
                    else:
                        try:
                            from core.factor_stats_manager import FACTOR_STATS
                            # Derive sample count for this factor
                            sc = FACTOR_STATS.get_sample_count(name)
                            if sc >= min_samples:
                                allow = True
                        except Exception:
                            allow = False
                    if allow:
                        # shrink to allowed delta (preserve sign)
                        cur = old + (max_delta if delta > 0 else -max_delta)
                    else:
                        # defer adjustment until more labeled samples available (retain old)
                        cur = old
                # Note: small updates or allowed deltas will be applied hereafter
                cur = max(min(cur, 1.0), -1.0)
                self._weights[name] = cur

    async def _persist_all(self):
        for f, w in list(self._weights.items()):
            await self._upsert_weight(f, w)

    async def _run_loop(self):
        await self._load_weights()
        logger.info('PersistentLearnerService started; interval=%s', self._interval)
        while not self._stopping:
            try:
                await self._scan_and_nudge()
                # persist periodically
                persist_every = int(__import__('os').environ.get('LEARNER_PERSIST_EVERY', '10') or 10)
                if persist_every and (int(time.time()) // self._interval) % persist_every == 0:
                    await self._persist_all()
            except Exception:
                logger.exception('Learner iteration failed')
            await asyncio.sleep(self._interval)
        # flush on stop
        try:
            await self._persist_all()
        except Exception:
            logger.debug('Failed to flush learned weights on stop')

    def start(self):
        if self._task:
            return
        loop = asyncio.get_event_loop()
        self._task = loop.create_task(self._run_loop())

    async def stop(self):
        self._stopping = True
        if self._task:
            await self._task

    def get_weights(self) -> Dict[str, float]:
        return dict(self._weights)


def get_learned_weights() -> Dict[str, float]:
    # convenience function used by risk_score; uses in-memory copy if service started
    # try to read runtime_state learner if present
    # During fast/test runs we avoid returning learned weights to keep unit tests
    # deterministic and order-independent. Tests set FAST_TEST_MODE in
    # `tests/conftest.py` to speed imports; honor that here.
    try:
        if str(__import__('os').environ.get('FAST_TEST_MODE', '0')).lower() in {'1', 'true', 'yes'}:
            return {}
    except Exception:
        pass
    try:
        from src.api import runtime_state as _rt
        ls = getattr(_rt, 'learner', None)
        if ls and hasattr(ls, 'get_weights'):
            return ls.get_weights()
    except Exception:
        pass
    return {}


def apply_decay(factor: str, decay: float = 0.995):
    try:
        from src.api import runtime_state as _rt
        ls = getattr(_rt, 'learner', None)
        if ls and hasattr(ls, '_weights'):
            ls._weights[factor] = ls._weights.get(factor, 0.0) * decay
    except Exception:
        pass
