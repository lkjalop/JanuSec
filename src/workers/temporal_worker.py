from __future__ import annotations
"""Async temporal task worker.

Polls `temporal_tasks` table for unprocessed tasks, evaluates expressions using
`src.rules.temporal_executor` (async wrappers), and creates incidents using
`incidents` table with deduplication (unique tenant_id+incident_key).

This worker is intentionally simple and uses asyncio to parallelize task processing.
"""
import asyncio, time, json, logging
from typing import Any, Optional
import psycopg2, os
try:
    from prometheus_client import Histogram, Counter, start_http_server
except Exception:
    # Fallback no-op implementations for test environments without prometheus_client
    class _NoopMetric:
        def __init__(self, *a, **k):
            pass
        def observe(self, *a, **k):
            pass
        def inc(self, *a, **k):
            pass
        def set(self, *a, **k):
            pass

    Histogram = _NoopMetric
    Counter = _NoopMetric
    def start_http_server(port):
        return None
import hashlib

DB_DSN = os.getenv('JNS_DB_DSN', 'postgresql://postgres:postgres@localhost:5432/janusec')

TASK_POLL_INTERVAL = float(os.getenv('TEMPORAL_WORKER_POLL', '1.0'))
METRICS_PORT = int(os.getenv('TEMPORAL_METRICS_PORT', '8000'))
RETRY_COUNT = int(os.getenv('TEMPORAL_WORKER_RETRIES', '3'))
RETRY_BACKOFF = float(os.getenv('TEMPORAL_WORKER_BACKOFF', '0.2'))


LOG = logging.getLogger('temporal_worker')
LOG.setLevel(os.getenv('TEMPORAL_WORKER_LOG_LEVEL','INFO'))
_h = logging.StreamHandler()
_h.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
LOG.addHandler(_h)

LATENCY_HIST = Histogram('janusec_temporal_latency_seconds', 'Temporal evaluation latency')
INCIDENTS_CREATED = Counter('janusec_incidents_created_total', 'Incidents auto-created')

def _get_conn():
    return psycopg2.connect(DB_DSN)

def _retry_db(func, *args, retries: int = None, backoff: float = None, **kwargs):
    retries = RETRY_COUNT if retries is None else retries
    backoff = RETRY_BACKOFF if backoff is None else backoff
    for i in range(retries):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            LOG.warning('DB op failed (%s), retry %d/%d', e, i+1, retries)
            time.sleep(backoff * (2 ** i))
    raise

def _fetch_event_raw(event_id: Optional[str]) -> Optional[dict]:
    if not event_id:
        return None
    try:
        def _fn():
            conn = _get_conn()
            with conn.cursor() as cur:
                cur.execute('SELECT raw FROM events WHERE event_id = %s', (event_id,))
                row = cur.fetchone()
            conn.close()
            if not row:
                return None
            raw = row[0]
            if isinstance(raw, str):
                try:
                    return json.loads(raw)
                except Exception:
                    return None
            return raw
        return _retry_db(_fn)
    except Exception:
        LOG.exception('Failed to fetch event %s', event_id)
        return None

async def _process_task_row(row: tuple[Any]):
    # row: (id, tenant_id, factor_id, event_id, rule_expr, ast)
    tid, tenant_id, factor_id, event_id, rule_expr, ast = row
    try:
        from src.rules.dsl_parser import parse_rule
        from src.rules.temporal_executor import async_execute_sequence, async_execute_absence, async_evaluate_rate, async_evaluate_zscore
    except Exception:
        return False
    # parse rule
    try:
        ast_node = parse_rule(rule_expr)
    except Exception:
        return False
    # Determine node type
    from src.rules.dsl_parser import Sequence, Absence, RateExpr, ZScoreExpr, LookupExpr
    start = time.time()
    matched = False
    try:
        if isinstance(ast_node, Sequence):
            matched = await async_execute_sequence(ast_node.steps, int(ast_node.window * (60 if ast_node.unit=='m' else 1)), tenant_id)
        elif isinstance(ast_node, Absence):
            matched = await async_execute_absence(ast_node.predicate, int(ast_node.window * (60 if ast_node.unit=='m' else 1)), tenant_id)
        elif isinstance(ast_node, RateExpr):
            matched = await async_evaluate_rate(ast_node.field, int(ast_node.window * (60 if ast_node.unit=='m' else 1)), ast_node.op, ast_node.threshold, tenant_id)
        elif isinstance(ast_node, ZScoreExpr):
            matched = await async_evaluate_zscore(ast_node.field, int(ast_node.window * (60 if ast_node.unit=='m' else 1)), ast_node.op, ast_node.threshold, tenant_id)
    except Exception:
        matched = False
    LATENCY_HIST.observe(time.time() - start)
    # Mark task processed (best-effort with retry)
    try:
        def _mark():
            conn = _get_conn()
            with conn.cursor() as cur:
                cur.execute("UPDATE temporal_tasks SET processed=TRUE, processed_at=now() WHERE id=%s", (tid,))
            conn.commit(); conn.close()
        _retry_db(_mark)
    except Exception as e:
        LOG.exception('Failed to mark temporal task %s processed', tid)
    # If matched, create deduped incident
    if matched:
        # Deterministic incident key: fetch original event raw payload and prefer canonical fields
        try:
            ev_raw = _fetch_event_raw(event_id)
        except Exception:
            ev_raw = None
        try:
            key_parts = [str(factor_id)]
            minute = int(time.time() // 60)
            if ev_raw and isinstance(ev_raw, dict):
                        # Build canonical fingerprint from available keys
                        cand = []
                        for fld in ('user','user_id','actor','actor_principal','src_ip','dst_ip','file_hash'):
                            v = ev_raw.get(fld) or ev_raw.get(f'{fld}')
                            if v:
                                cand.append(f"{fld}={v}")
                        if cand:
                            # stable sort and hash
                            s = '|'.join(sorted(cand))
                            fp = hashlib.sha256(s.encode('utf-8')).hexdigest()[:16]
                            key_parts.append(fp)
            else:
                key_parts.append(str(event_id))
            key_parts.append(str(minute))
            key = 'auto:' + ':'.join(key_parts)
        except Exception:
            key = f"auto:{factor_id}:{int(time.time()//60)}"
        try:
            def _ins():
                conn = _get_conn()
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO incidents(tenant_id,incident_key,title,description,severity,metadata) VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT (tenant_id,incident_key) DO UPDATE SET updated_at=now(), metadata=incidents.metadata",
                        (tenant_id, key, f'Auto:{factor_id}', f'Auto-generated incident for {factor_id}', 'HIGH', json.dumps({'factor':factor_id, 'event': event_id}))
                    )
                conn.commit(); conn.close()
            _retry_db(_ins)
            INCIDENTS_CREATED.inc()
            LOG.info('Created/updated incident %s for tenant=%s factor=%s', key, tenant_id, factor_id)
        except Exception:
            LOG.exception('Failed to create incident for task %s', tid)
    return matched

async def run_worker():
    loop = asyncio.get_event_loop()
    # Start Prometheus metrics server
    try:
        start_http_server(METRICS_PORT)
        LOG.info('Prometheus metrics available on :%d', METRICS_PORT)
    except Exception:
        LOG.exception('Failed to start Prometheus metrics HTTP server')
    while True:
        try:
            conn = _get_conn()
            with conn.cursor() as cur:
                cur.execute("SELECT id, tenant_id, factor_id, event_id, rule_expr, ast FROM temporal_tasks WHERE processed=FALSE ORDER BY created_at LIMIT 50")
                rows = cur.fetchall()
            conn.close()
            if not rows:
                await asyncio.sleep(TASK_POLL_INTERVAL)
                continue
            tasks = [loop.create_task(_process_task_row(r)) for r in rows]
            await asyncio.gather(*tasks)
        except Exception:
            LOG.exception('Worker loop error, sleeping')
            await asyncio.sleep(TASK_POLL_INTERVAL)

if __name__ == '__main__':
    asyncio.run(run_worker())
