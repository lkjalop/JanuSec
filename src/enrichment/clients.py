"""Defensive reputation client helpers used by background tasks.

This module provides a minimal, safe implementation of the public helpers
used by the codebase and tests. The real implementation may perform HTTP
requests to external reputation services; for tests and constrained CI
environments we avoid network calls and behave gracefully when dependencies
or configuration are missing.
"""
from __future__ import annotations
import os
import asyncio
import time
from typing import Optional, Dict, Any
from src.enrichment.cache import get as cache_get, set_ as cache_set
try:
    from src.enrichment.kev_epss import kev_lookup
except Exception:
    try:
        from enrichment.kev_epss import kev_lookup  # type: ignore
    except Exception:
        kev_lookup = None  # type: ignore


async def fetch_epss_for_hash(sha256: str) -> Optional[Dict[str, Any]]:
    """Return a cached or best-effort EPSS result for `sha256`.

    In this lightweight implementation we do not perform network calls.
    If `EPSS_API_KEY` is not configured we return a deterministic low-risk
    mock and cache it. If an API key is present we avoid network access and
    return None so callers treat it as unavailable.
    """
    key = f"hash:{sha256}"
    try:
        cached = cache_get(key)
        if cached:
            return cached
    except Exception:
        # Cache layer might be disabled in tests; continue defensively
        cached = None

    api_key = os.getenv("EPSS_API_KEY")
    if not api_key:
        mock = {"epss_score": 0.0, "source": "mock"}
        try:
            cache_set(key, mock)
        except Exception:
            pass
        return mock

    # In CI/test environments we avoid external calls; signal unavailability
    return None


async def fetch_kev_for_cve(cve: str) -> Optional[Dict[str, Any]]:
    """Return a cached or best-effort KEV result for `cve`.

    This lightweight implementation avoids network calls and relies on
    in-memory KEV ingestion when available. If no KEV source is configured
    we return a deterministic mock entry so callers can proceed.
    """
    key = f"cve:{cve}"
    try:
        cached = cache_get(key)
        if cached:
            return cached
    except Exception:
        cached = None

    kev = None
    try:
        if kev_lookup is not None:
            kev = kev_lookup(cve)
    except Exception:
        kev = None

    if kev:
        try:
            cache_set(key, {"cve": cve, "kev": True, "source": "kev_db", "data": kev})
        except Exception:
            pass
        return {"cve": cve, "kev": True, "source": "kev_db", "data": kev}

    # No feed configured or entry missing; emit a low-risk placeholder
    mock = {"cve": cve, "kev": False, "source": "mock"}
    try:
        cache_set(key, mock)
    except Exception:
        pass
    return mock


def schedule_background_fetch(coro):
    """Schedule a coroutine to run in the current or a new event loop.

    This helper attempts to create a background task when an event loop is
    running; otherwise it runs the coroutine to completion. It swallows
    exceptions to keep callers best-effort.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(coro)
        else:
            loop.run_until_complete(coro)
    except Exception:
        try:
            asyncio.create_task(coro)
        except Exception:
            pass


def _emit_epss_factor(sha256: str, body: Dict[str, Any]):
    """Best-effort emission of an EPSS-derived factor into event sinks.

    The function will try to push a small event into `EVENT_QUEUE` if it
    exists, otherwise attempt to upsert/ingest a hopgraph event. All
    operations are best-effort and exceptions are ignored.
    """
    try:
        score = float((body or {}).get("epss_score", 0.0) or 0.0)
    except Exception:
        score = 0.0
    try:
        thresh = float(os.getenv("ENRICH_EPSS_THRESHOLD", "0.5") or 0.5)
    except Exception:
        thresh = 0.5

    if score < thresh:
        return

    evt = {"type": "enrichment:epss_high", "hash": sha256, "score": score, "ts": int(time.time())}
    try:
        from src.api.runtime_state import EVENT_QUEUE

        try:
            EVENT_QUEUE.put(evt)
            return
        except Exception:
            pass
    except Exception:
        pass

    try:
        from src.graph.hopgraph import GLOBAL_HOPGRAPH
        if GLOBAL_HOPGRAPH is not None:
            try:
                from src.core.graph.hopgraph_utils import safe_upsert_node
            except Exception:
                safe_upsert_node = None

            try:
                if safe_upsert_node is not None:
                    safe_upsert_node(GLOBAL_HOPGRAPH, "file_hash", sha256, attrs={"epss_score": score, "source": "epss"}, source="enrichment:epss")
                elif hasattr(GLOBAL_HOPGRAPH, "ingest_event"):
                    GLOBAL_HOPGRAPH.ingest_event(evt, source="enrichment:epss")
            except Exception:
                pass
    except Exception:
        pass

