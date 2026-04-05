"""Batch persona pre-generation worker.

Runs as a background daemon thread that watches for new triage batches (or
specific report IDs) and pre-generates all persona views for the analyst
dashboard.  Views are cached so that UI requests return instantly without
waiting for LLM / persona-view computation at request-time.

Architecture::

    Triage batch result
          ↓
     [BatchPersonaWorker]   ← background thread
          ↓  (for each alert in persona queues)
     generate_persona_view()       ← respects analyst gate
          ↓
     PersonaViewCache              ← in-memory + optional disk persist
          ↓  (UI polls)
     GET /api/v1/persona/views/{report_id}/{persona}

Worker lifecycle:
  - Started once via ``start_worker()``; call ``stop_worker()`` on shutdown.
  - ``enqueue(triage_result, report_lookup)`` → non-blocking, adds to job queue
  - Worker thread pops jobs, calls ``route_personas()``, stores results in cache.
  - Cache entries expire after ``PERSONA_CACHE_TTL_SECONDS`` (default 3600 s).

Config env vars::

    PERSONA_CACHE_TTL_SECONDS   — view TTL (default 3600)
    PERSONA_WORKER_THREADS      — parallel worker threads (default 2)
    PERSONA_MAX_QUEUE            — max pending jobs before shedding (default 200)
"""
from __future__ import annotations

import logging
import os
import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

_CACHE_TTL = int(os.getenv('PERSONA_CACHE_TTL_SECONDS', '3600'))
_WORKER_THREADS = max(1, int(os.getenv('PERSONA_WORKER_THREADS', '2')))
_MAX_QUEUE = int(os.getenv('PERSONA_MAX_QUEUE', '200'))


# ── Cache ─────────────────────────────────────────────────────────────

@dataclass
class _CacheEntry:
    views: Dict[str, Any]        # keyed by persona name
    generated_ts: float = field(default_factory=time.time)
    triage_tier: str = 'P4'


class PersonaViewCache:
    """Thread-safe LRU-ish cache for pre-generated persona views."""

    def __init__(self, ttl_seconds: int = _CACHE_TTL) -> None:
        self._ttl = ttl_seconds
        self._store: Dict[str, _CacheEntry] = {}
        self._lock = threading.Lock()

    def put(self, report_id: str, views: Dict[str, Any], tier: str = 'P4') -> None:
        with self._lock:
            self._store[report_id] = _CacheEntry(views=views, triage_tier=tier)

    def get(self, report_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            entry = self._store.get(report_id)
            if not entry:
                return None
            if time.time() - entry.generated_ts > self._ttl:
                del self._store[report_id]
                return None
            return entry.views

    def get_persona(self, report_id: str, persona: str) -> Optional[Dict[str, Any]]:
        views = self.get(report_id)
        return views.get(persona) if views else None

    def list_cached(self) -> List[str]:
        with self._lock:
            now = time.time()
            return [rid for rid, e in self._store.items()
                    if now - e.generated_ts <= self._ttl]

    def evict_expired(self) -> int:
        with self._lock:
            now = time.time()
            expired = [k for k, e in self._store.items()
                       if now - e.generated_ts > self._ttl]
            for k in expired:
                del self._store[k]
        return len(expired)

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            now = time.time()
            live = [e for e in self._store.values() if now - e.generated_ts <= self._ttl]
            return {
                'total_entries': len(self._store),
                'live_entries': len(live),
                'ttl_seconds': self._ttl,
            }


# ── Job ───────────────────────────────────────────────────────────────

@dataclass
class PersonaJob:
    triage_result: Any            # TriageResult from tiered_triage
    report_lookup: Optional[Any]  # dict or callable for full reports
    priority: int = 5             # lower = higher priority (P1 → 1)


# ── Worker ────────────────────────────────────────────────────────────

class BatchPersonaWorker:
    """Background worker that drains a job queue and populates PersonaViewCache."""

    def __init__(
        self,
        cache: Optional[PersonaViewCache] = None,
        n_threads: int = _WORKER_THREADS,
    ) -> None:
        self.cache = cache or PersonaViewCache()
        self._queue: queue.PriorityQueue = queue.PriorityQueue(maxsize=_MAX_QUEUE)
        self._threads: List[threading.Thread] = []
        self._stop_event = threading.Event()
        self.n_threads = n_threads
        self._stats = {
            'jobs_processed': 0,
            'jobs_failed': 0,
            'views_generated': 0,
        }
        self._stats_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start worker threads."""
        if self._threads:
            return
        for i in range(self.n_threads):
            t = threading.Thread(
                target=self._loop,
                name=f'persona-worker-{i}',
                daemon=True,
            )
            t.start()
            self._threads.append(t)
        logger.info('BatchPersonaWorker started with %d threads', self.n_threads)

    def stop(self, timeout: float = 5.0) -> None:
        """Signal threads to stop and wait for them to drain."""
        self._stop_event.set()
        for t in self._threads:
            t.join(timeout=timeout)
        self._threads.clear()
        logger.info('BatchPersonaWorker stopped')

    # ------------------------------------------------------------------
    # Enqueue
    # ------------------------------------------------------------------

    def enqueue(
        self,
        triage_result: Any,
        report_lookup: Optional[Any] = None,
    ) -> bool:
        """Non-blocking enqueue. Returns False if queue is full (shedding)."""
        # Determine priority from highest tier present
        tiers = getattr(triage_result, 'tiers', {})
        priority = 5
        if tiers.get('P1'):
            priority = 1
        elif tiers.get('P2'):
            priority = 2
        elif tiers.get('P3'):
            priority = 3

        job = PersonaJob(
            triage_result=triage_result,
            report_lookup=report_lookup,
            priority=priority,
        )
        try:
            # PriorityQueue uses (priority, counter, item) tuples
            self._queue.put_nowait((priority, time.time(), job))
            return True
        except queue.Full:
            logger.warning('Persona worker queue full; shedding job (priority=%d)', priority)
            return False

    def enqueue_report(
        self,
        report: Dict[str, Any],
        tier: str = 'P3',
    ) -> bool:
        """Enqueue a single report without going through triage first.

        Creates a minimal synthetic TriageResult wrapping the report so that
        the worker can call route_personas() uniformly.
        """
        try:
            from src.reporting.tiered_triage import (
                TriageConfig, TriageResult, ScoredAlert, triage_alerts
            )
            # Score the report and create a TriageResult
            result = triage_alerts([report])
        except Exception as exc:
            logger.warning('enqueue_report: triage_alerts failed: %s', exc)
            return False

        return self.enqueue(
            triage_result=result,
            report_lookup={
                (report.get('report_id') or report.get('id') or ''): report
            },
        )

    # ------------------------------------------------------------------
    # Worker loop
    # ------------------------------------------------------------------

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                try:
                    _, _, job = self._queue.get(timeout=1.0)
                except queue.Empty:
                    continue
                self._process(job)
                self._queue.task_done()
            except Exception as exc:
                logger.error('Persona worker loop error: %s', exc, exc_info=True)
                with self._stats_lock:
                    self._stats['jobs_failed'] += 1

    def _process(self, job: PersonaJob) -> None:
        """Process one job: generate all persona views and cache them."""
        try:
            from src.reporting.persona_router import route_personas
            persona_views = route_personas(
                job.triage_result,
                report_lookup=job.report_lookup,
            )

            # Cache per-report
            view_count = 0
            tiers = getattr(job.triage_result, 'tiers', {})
            for persona, views in persona_views.items():
                for view in views:
                    report_id = view.get('report_id') or view.get('alert_id')
                    if not report_id:
                        continue
                    # tier for this report
                    tier = view.get('tier', 'P4')
                    existing = self.cache.get(report_id) or {}
                    existing[persona] = view
                    self.cache.put(report_id, existing, tier=tier)
                    view_count += 1

            with self._stats_lock:
                self._stats['jobs_processed'] += 1
                self._stats['views_generated'] += view_count

            logger.debug('Persona worker: processed job → %d views cached', view_count)
        except Exception as exc:
            logger.error('Persona job processing failed: %s', exc, exc_info=True)
            with self._stats_lock:
                self._stats['jobs_failed'] += 1

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        with self._stats_lock:
            s = dict(self._stats)
        s['queue_depth'] = self._queue.qsize()
        s['cache_stats'] = self.cache.stats()
        s['threads_alive'] = sum(1 for t in self._threads if t.is_alive())
        return s


# ── Singletons ────────────────────────────────────────────────────────

_GLOBAL_CACHE: Optional[PersonaViewCache] = None
_GLOBAL_WORKER: Optional[BatchPersonaWorker] = None


def get_persona_cache() -> PersonaViewCache:
    global _GLOBAL_CACHE
    if _GLOBAL_CACHE is None:
        _GLOBAL_CACHE = PersonaViewCache()
    return _GLOBAL_CACHE


def get_persona_worker() -> BatchPersonaWorker:
    global _GLOBAL_WORKER
    if _GLOBAL_WORKER is None:
        _GLOBAL_WORKER = BatchPersonaWorker(cache=get_persona_cache())
    return _GLOBAL_WORKER


def start_worker() -> BatchPersonaWorker:
    """Start the global worker. Safe to call multiple times."""
    worker = get_persona_worker()
    worker.start()
    return worker


def stop_worker() -> None:
    global _GLOBAL_WORKER
    if _GLOBAL_WORKER is not None:
        _GLOBAL_WORKER.stop()
