from __future__ import annotations
import os, time
import psycopg2
from src.graph.neo4j_bridge import upsert_event_node, upsert_resource_node

DB_DSN = os.getenv('JNS_DB_DSN', 'postgresql://postgres:postgres@localhost:5432/janusec')


def _get_conn():
    return psycopg2.connect(DB_DSN)


def run_backfill(batch: int = 100):
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute('SELECT event_id, raw FROM events ORDER BY ts ASC LIMIT %s', (batch,))
            rows = cur.fetchall()
            for eid, raw in rows:
                try:
                    ev = {'event_id': eid, 'ts': raw.get('published') if isinstance(raw, dict) else None, 'domain': (raw.get('domain') if isinstance(raw, dict) else None) or 'unknown', 'actor': raw.get('actor') if isinstance(raw, dict) else {}}
                    upsert_event_node(ev)
                    # upsert resource if present
                    obj = (raw.get('object') if isinstance(raw, dict) else None) or raw.get('resourceId')
                    if obj:
                        upsert_resource_node(str(obj), {'sample': True})
                except Exception:
                    continue
    finally:
        conn.close()


if __name__ == '__main__':
    run_backfill(1000)
