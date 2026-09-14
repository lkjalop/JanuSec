"""Background enrichment worker: seeds reputation/enrichment cache by scanning
recent sessions and calling EPSS/KEV clients.

This worker is safe to run in production when configured via env vars. It
respects FAST_TEST_MODE and will skip long sleeps when tests run.
"""
from __future__ import annotations
import asyncio
import os
import time
import logging
from typing import List

logger = logging.getLogger(__name__)

try:
    from src.enrichment.clients import fetch_epss_for_hash, fetch_kev_for_cve
except Exception:
    # fall back to local import paths
    from enrichment.clients import fetch_epss_for_hash, fetch_kev_for_cve

try:
    from src.api.session_store import get_session_store
except Exception:
    get_session_store = None


async def _seed_from_sessions(limit: int = 200):
    """Scan recent sessions for hashes and CVEs and fetch reputations."""
    try:
        store = None
        if get_session_store:
            try:
                store = get_session_store()
            except Exception:
                store = None
        sessions = []
        if store is not None:
            try:
                # store.all() may be large; limit seeks
                sessions = list(store.all())[-limit:]
            except Exception:
                sessions = []
        else:
            # fallback scan data/sessions dir
            sd = os.path.join(os.path.dirname(__file__), '..', 'data', 'sessions')
            sd = os.path.abspath(sd)
            if os.path.exists(sd):
                try:
                    files = sorted([os.path.join(sd, p) for p in os.listdir(sd) if p.endswith('.json')])[-limit:]
                    import json
                    for f in files:
                        try:
                            with open(f, 'r', encoding='utf-8') as fh:
                                sessions.append(json.load(fh))
                        except Exception:
                            continue
                except Exception:
                    sessions = []

        hashes = set()
        cves = set()
        for s in sessions:
            try:
                canon = s.get('canonical') or {}
                h = canon.get('file_hash') or canon.get('sha256')
                if h:
                    hashes.add(h)
                # also look for CVE tokens in shadow data
                crq = s.get('crq_shadow') or {}
                if isinstance(crq, dict):
                    for v in crq.get('observations', []) if isinstance(crq.get('observations', []), list) else []:
                        if isinstance(v, dict) and v.get('cve'):
                            cves.add(v.get('cve'))
            except Exception:
                continue

        # Seed EPSS for recent hashes
        for h in list(hashes)[:100]:
            try:
                await fetch_epss_for_hash(h)
            except Exception:
                logger.debug('Failed epss fetch for %s', h, exc_info=True)

        # Seed KEV for CVEs
        for c in list(cves)[:100]:
            try:
                await fetch_kev_for_cve(c)
            except Exception:
                logger.debug('Failed kev fetch for %s', c, exc_info=True)
    except Exception:
        logger.exception('Seed job failed')


async def seed_worker_loop(interval_seconds: int = 3600):
    """Worker loop: run seeding job periodically."""
    short = os.getenv('FAST_TEST_MODE','0').lower() in {'1','true','yes'}
    if short:
        interval_seconds = 2
    while True:
        try:
            await _seed_from_sessions(limit=500)
        except Exception:
            logger.exception('seed_from_sessions error')
        await asyncio.sleep(max(2, interval_seconds))


def register_seed_worker(app):
    try:
        if os.getenv('ENABLE_ENRICHMENT_WORKER','0').lower() in {'1','true','yes'}:
            interval = int(os.getenv('ENRICH_SEED_INTERVAL_SECONDS', '3600') or 3600)
            if os.getenv('FAST_TEST_MODE','0').lower() in {'1','true','yes'}:
                interval = 2
            app.add_event_handler('startup', lambda: asyncio.create_task(seed_worker_loop(interval)))
    except Exception:
        logger.exception('Failed to register seed worker')
