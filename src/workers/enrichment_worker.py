"""Background worker to process enrichment_queue and run email enrichment."""
from __future__ import annotations

import asyncio
import json
import logging
import time
import os
from typing import Any

from src.enrichment.email_enrichment import enrich_email
from src.graph.ingest import ingest_event

logger = logging.getLogger(__name__)


class EnrichmentWorker:
    """Consume enrichment_queue and enrich events.

    Supports Postgres async pool (asyncpg) and a lightweight sqlite connection
    (sync) used in dev/test fallback. When HopGraph client is available on the
    app or passed in, it will attempt to ingest artifacts.
    """

    def __init__(self, db_pool_or_conn, hopgraph=None):
        self.db = db_pool_or_conn
        self.hopgraph = hopgraph

    async def run(self):
        while True:
            try:
                # Try asyncpg-style pool first
                if hasattr(self.db, 'acquire'):
                    async with self.db.acquire() as conn:
                        rows = await conn.fetch("SELECT id, tenant_id, event_id FROM enrichment_queue LIMIT 10")
                        for r in rows:
                            await self._process_with_asyncpg(conn, r)
                else:
                    # sqlite fallback: expect a simple connection object with execute/fetchall
                    try:
                        cur = self.db.cursor()
                        cur.execute("SELECT id, tenant_id, event_id FROM enrichment_queue LIMIT 10")
                        rows = cur.fetchall()
                        for r in rows:
                            await self._process_with_sqlite(cur, r)
                    except Exception:
                        logger.exception('sqlite enrichment processing failed')
            except Exception:
                logger.exception('enrichment loop error')
            await asyncio.sleep(1)

    async def _process_with_asyncpg(self, conn, row):
        try:
            id_ = row['id']
            tenant = row['tenant_id']
            event_id = row['event_id']
            ev = await conn.fetchrow("SELECT raw FROM events WHERE event_id=$1", event_id)
            if not ev:
                await conn.execute("DELETE FROM enrichment_queue WHERE id=$1", id_)
                return
            raw = ev['raw'] if isinstance(ev['raw'], dict) else json.loads(ev['raw'])
            enrich = enrich_email(raw)
            newf = (raw.get('factors') or []) + (enrich.get('signals') or [])
            raw['factors'] = newf
            await conn.execute("UPDATE events SET raw=$1 WHERE event_id=$2", json.dumps(raw), event_id)
            # HopGraph ingest if available
            if os.getenv('HOPGRAPH_INGEST_ENABLED','0').lower() in {'1','true','yes'}:
                try:
                    # Build a compact payload for HopGraph from the enriched event
                    payload = {
                        'src_host': raw.get('context', {}).get('host') or raw.get('host') or raw.get('src_host'),
                        'dst_ip': raw.get('context', {}).get('dst_ip') or raw.get('dst_ip') or raw.get('destination_ip'),
                        'domain': raw.get('context', {}).get('domain') or raw.get('domain') or raw.get('hostname'),
                        'process': raw.get('context', {}).get('process') or raw.get('process') or raw.get('proc_name'),
                        'ts': raw.get('ts') or raw.get('timestamp') or time.time(),
                    }
                    try:
                        try:
                            from src.core.graph.hopgraph_utils import safe_upsert_node
                        except Exception:
                            safe_upsert_node = None
                        if payload.get('type') == 'file_hash' and (payload.get('id') or payload.get('hash')) and safe_upsert_node is not None:
                            fid = payload.get('id') or payload.get('hash')
                            try:
                                safe_upsert_node(GLOBAL_HOPGRAPH, 'file_hash', fid, attrs=payload.get('attrs') or {}, source='email_enrichment')
                            except Exception:
                                try:
                                    ingest_event(payload, source='email_enrichment')
                                except Exception:
                                    logger.debug('ingest_event() failed in asyncpg path')
                        else:
                            try:
                                ingest_event(payload, source='email_enrichment')
                            except Exception:
                                logger.debug('ingest_event() failed in asyncpg path')
                    except Exception:
                        logger.debug('ingest_event() failed in asyncpg path')
                except Exception:
                    logger.debug('hopgraph ingest construction failed')
            await conn.execute("DELETE FROM enrichment_queue WHERE id=$1", id_)
        except Exception:
            logger.exception('failed processing enrichment row')

    async def _process_with_sqlite(self, cur, row):
        try:
            # sqlite cursor row tuple ordering: (id, tenant, event_id)
            id_, tenant, event_id = row
            cur.execute("SELECT raw FROM events WHERE event_id=?", (event_id,))
            r = cur.fetchone()
            if not r:
                cur.execute("DELETE FROM enrichment_queue WHERE id=?", (id_,))
                self.db.commit()
                return
            raw_blob = r[0]
            try:
                raw = json.loads(raw_blob) if isinstance(raw_blob, str) else raw_blob
            except Exception:
                raw = {}
            enrich = enrich_email(raw)
            newf = (raw.get('factors') or []) + (enrich.get('signals') or [])
            raw['factors'] = newf
            cur.execute("UPDATE events SET raw=? WHERE event_id=?", (json.dumps(raw), event_id))
            # hopgraph ingest if available
            if os.getenv('HOPGRAPH_INGEST_ENABLED','0').lower() in {'1','true','yes'}:
                try:
                    payload = {
                        'src_host': raw.get('context', {}).get('host') or raw.get('host') or raw.get('src_host'),
                        'dst_ip': raw.get('context', {}).get('dst_ip') or raw.get('dst_ip') or raw.get('destination_ip'),
                        'domain': raw.get('context', {}).get('domain') or raw.get('domain') or raw.get('hostname'),
                        'process': raw.get('context', {}).get('process') or raw.get('process') or raw.get('proc_name'),
                        'ts': raw.get('ts') or raw.get('timestamp') or time.time(),
                    }
                    try:
                        try:
                            from src.core.graph.hopgraph_utils import safe_upsert_node
                        except Exception:
                            safe_upsert_node = None
                        if payload.get('type') == 'file_hash' and (payload.get('id') or payload.get('hash')) and safe_upsert_node is not None:
                            fid = payload.get('id') or payload.get('hash')
                            try:
                                safe_upsert_node(GLOBAL_HOPGRAPH, 'file_hash', fid, attrs=payload.get('attrs') or {}, source='email_enrichment')
                            except Exception:
                                try:
                                    ingest_event(payload, source='email_enrichment')
                                except Exception:
                                    logger.debug('ingest_event() failed in sqlite path')
                        else:
                            try:
                                ingest_event(payload, source='email_enrichment')
                            except Exception:
                                logger.debug('ingest_event() failed in sqlite path')
                    except Exception:
                        logger.debug('ingest_event() failed in sqlite path')
                except Exception:
                    logger.debug('hopgraph ingest construction failed (sqlite path)')
            cur.execute("DELETE FROM enrichment_queue WHERE id=?", (id_,))
            self.db.commit()
        except Exception:
            logger.exception('sqlite enrichment processing failed')

    def stop(self):
        self._running = False


__all__ = ['EnrichmentWorker']
