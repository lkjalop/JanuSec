from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any

from src.adapters.bridge import ingest_vulns_from_connector

logger = logging.getLogger(__name__)


def push_to_pipeline(artifact: dict) -> None:
    """Placeholder ingestion forwarding function.

    Replace this with your real ingestion API/database call. Keep the
    operation quick and non-blocking; for heavy lifting push to a worker or
    message queue.
    """
    # Example: print as JSONL for demonstration
    print('INGEST:', json.dumps(artifact))


def run_once(client_id: str, client_secret: str, api_base: str = 'https://qualysapi.example.com'):
    for artifact in ingest_vulns_from_connector('qualys', client_id=client_id, client_secret=client_secret, api_base=api_base):
        try:
            push_to_pipeline(artifact)
        except Exception:
            logger.exception('Failed to push artifact to pipeline: %s', artifact)


async def _loop(client_id: str, client_secret: str, api_base: str, interval_seconds: int):
    while True:
        try:
            run_once(client_id, client_secret, api_base=api_base)
        except Exception:
            logger.exception('Qualys ingest iteration failed')
        await asyncio.sleep(max(10, interval_seconds))


def register_qualys_ingest_scheduler(app: Any) -> None:
    """Register a periodic Qualys ingestion scheduler on app startup.

    Controlled via env var `QUALYS_INGEST_SCHED_ENABLED` (0/1). Interval is
    `QUALYS_INGEST_INTERVAL_SECONDS` (default 3600).
    """
    enabled = os.getenv('QUALYS_INGEST_SCHED_ENABLED', '0').lower() in {'1', 'true', 'yes'}
    if not enabled:
        logger.debug('Qualys ingest scheduler not enabled')
        return

    try:
        interval = int(os.getenv('QUALYS_INGEST_INTERVAL_SECONDS', '3600') or 3600)
    except Exception:
        interval = 3600

    client_id = os.getenv('QUALYS_CLIENT_ID')
    client_secret = os.getenv('QUALYS_CLIENT_SECRET')
    api_base = os.getenv('QUALYS_API_BASE', 'https://qualysapi.example.com')

    if not client_id or not client_secret:
        logger.warning('Qualys credentials not set; scheduler will not start')
        return

    async def _starter():  # pragma: no cover - background loop
        await _loop(client_id, client_secret, api_base, interval)

    try:
        app.add_event_handler('startup', lambda: asyncio.create_task(_starter()))
        logger.info('Registered Qualys ingest scheduler (interval=%s)', interval)
    except Exception:
        try:
            loop = asyncio.get_event_loop()
            loop.create_task(_starter())
            logger.info('Registered Qualys ingest scheduler via event loop')
        except Exception:
            logger.exception('Failed to register Qualys ingest scheduler')


if __name__ == '__main__':
    # Allow ad-hoc local runs: read creds from env
    cid = os.environ.get('QUALYS_CLIENT_ID')
    secret = os.environ.get('QUALYS_CLIENT_SECRET')
    api = os.environ.get('QUALYS_API_BASE', 'https://qualysapi.example.com')
    if not cid or not secret:
        raise SystemExit('Set QUALYS_CLIENT_ID and QUALYS_CLIENT_SECRET in env')
    run_once(cid, secret, api_base=api)
"""Example scheduled job that wires the Qualys bridge into the ingestion pipeline.

Integrate this with your scheduler (cron, APScheduler, Celery beat, etc.).
Replace `push_to_pipeline()` with your real ingestion function.
"""
from src.adapters.bridge import ingest_vulns_from_connector
import json


def push_to_pipeline(artifact: dict):
    # Replace with your actual ingestion endpoint (db insert, API call, etc.)
    print('INGEST:', json.dumps(artifact))


def run_once(client_id: str, client_secret: str, api_base: str = 'https://qualysapi.example.com'):
    for artifact in ingest_vulns_from_connector('qualys', client_id=client_id, client_secret=client_secret, api_base=api_base):
        push_to_pipeline(artifact)


if __name__ == '__main__':
    import os
+    # Example: read creds from env for ad-hoc runs
+    cid = os.environ.get('QUALYS_CLIENT_ID')
+    secret = os.environ.get('QUALYS_CLIENT_SECRET')
+    if not cid or not secret:
+        raise SystemExit('Set QUALYS_CLIENT_ID and QUALYS_CLIENT_SECRET in env')
+    run_once(cid, secret)
