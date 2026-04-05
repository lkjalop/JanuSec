from __future__ import annotations
import os, time, json
from typing import Any, Dict
import psycopg2
from src.embedding.service import get_embedding_service
from src.metrics.embedding_metrics import set_queue_length, observe_latency, set_mode_model, set_mode_fallback

DB_DSN = os.getenv('JNS_DB_DSN', 'postgresql://postgres:postgres@localhost:5432/janusec')


def _get_conn():
    return psycopg2.connect(DB_DSN)


def process_batch(limit: int = 50):
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute('SELECT id, event_id FROM enrichment_queue ORDER BY queued_at ASC LIMIT %s FOR UPDATE SKIP LOCKED', (limit,))
            rows = cur.fetchall()
            set_queue_length(len(rows))
            svc = get_embedding_service()
            # set mode metric
            if svc._model is None:
                set_mode_fallback()
            else:
                set_mode_model()
            for rid, event_id in rows:
                # fetch event
                cur.execute('SELECT raw, factors FROM events WHERE event_id = %s', (event_id,))
                er = cur.fetchone()
                if not er:
                    cur.execute('DELETE FROM enrichment_queue WHERE id = %s', (rid,))
                    continue
                raw, factors = er
                # build event dict for embedding
                event = {'raw': raw, 'factors': factors}
                # generate embeddings
                start = time.time()
                vec = svc.embed_event(event)
                factor_vec = svc.embed_factors(factors or [])
                elapsed = time.time() - start
                observe_latency(elapsed)
                # update events row
                cur.execute('UPDATE events SET event_semantic_vector = %s, factor_context_vector = %s WHERE event_id = %s', (vec, factor_vec, event_id))
                # remove from queue
                cur.execute('DELETE FROM enrichment_queue WHERE id = %s', (rid,))
        conn.commit()
    finally:
        conn.close()


if __name__ == '__main__':
    while True:
        process_batch(20)
        time.sleep(2)
