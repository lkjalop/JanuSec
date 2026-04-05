"""Adapter providing a unified decisions_repo.persist API used by server.

If a full DB-backed repo is present (repositories.decisions_repo with upsert_decision),
this adapter will call it. Otherwise it keeps an in-memory list for testing.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List, Optional

_IN_MEMORY: List[Dict[str, Any]] = []


class DecisionsRepoAdapter:
    def __init__(self):
        # attempt lazy import of real repo
        self._real = None
        try:
            import repositories.decisions_repo as dr
            self._real = dr
        except Exception:
            self._real = None

    async def persist(self, decision: Dict[str, Any]) -> None:
        """Persist decision. If DB repo present use its async upsert; otherwise store in-memory."""
        if self._real and hasattr(self._real, 'upsert_decision'):
            # construct a minimal object that matches legacy callsite expectations
            class _D:
                pass
            d = _D()
            # map common attributes
            d.factors = decision.get('factors', [])
            d.verdict = decision.get('verdict')
            d.confidence = float(decision.get('confidence') or 0.0)
            d.processing_time_ms = float(decision.get('processing_time_ms') or 0.0)
            d.stage_timings = decision.get('stage_timings') or {}
            d.custody_hash = decision.get('custody_hash') if 'custody_hash' in decision else None
            tenant_id = decision.get('tenant_id')
            try:
                coro = self._real.upsert_decision(decision.get('event_id'), d, tenant_id)
                # If the upsert_decision is a coroutine, run appropriately
                if asyncio.iscoroutine(coro):
                    try:
                        loop = asyncio.get_event_loop()
                        if loop.is_running():
                            await coro
                        else:
                            # run to completion in a new loop
                            asyncio.run(coro)
                    except Exception:
                        # fallback to awaitable runner
                        try:
                            asyncio.run(coro)
                        except Exception:
                            _IN_MEMORY.append(dict(decision))
                else:
                    # not a coroutine, assume sync
                    _ = coro
            except Exception:
                # best-effort: fall back to in-memory
                _IN_MEMORY.append(dict(decision))
        else:
            # store shallow copy
            _IN_MEMORY.append(dict(decision))

    async def persist_learned_weights(self, weights: Dict[str, float]) -> None:
        """Persist learned weights into the in-memory store for tests and local runs."""
        _IN_MEMORY.append({'event_id': f'learner-{int(time.time())}', 'meta': {'learned_weights': weights}})

    async def list_recent_decisions(self, limit: int = 50, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        # mimic DB repo list_recent signature
        from itertools import islice
        if tenant_id is None:
            return list(islice(reversed(_IN_MEMORY), 0, limit))
        # filter by tenant_id
        filtered = [d for d in reversed(_IN_MEMORY) if d.get('tenant_id') == tenant_id]
        return list(islice(filtered, 0, limit))

    def list_memory(self) -> List[Dict[str, Any]]:
        return list(_IN_MEMORY)


repo = DecisionsRepoAdapter()
