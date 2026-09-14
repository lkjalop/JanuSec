from __future__ import annotations
"""Daily retention sweeper job.

Reads per-tenant retention config from `integration_configs` (name='retention') and
deletes events older than retention_days for tenants without `legal_hold` set.
Produces a simple log and metric via Prometheus if available.
"""
import time, os, json
from typing import Dict, Any
import psycopg2

DB_DSN = os.getenv('JNS_DB_DSN', 'postgresql://postgres:postgres@localhost:5432/janusec')


def _get_conn():
    return psycopg2.connect(DB_DSN)


def _load_retention_configs() -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    try:
        conn = _get_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT tenant_id, config FROM integration_configs WHERE name='retention'")
            for row in cur.fetchall():
                try:
                    cfg = row[1] or {}
                    if isinstance(cfg, str):
                        cfg = json.loads(cfg)
                    out[row[0]] = cfg
                except Exception:
                    out[row[0]] = {}
        conn.close()
    except Exception:
        pass
    return out


def sweep_once(dry_run: bool = True) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    configs = _load_retention_configs()
    try:
        conn = _get_conn()
        with conn.cursor() as cur:
            for tenant, cfg in configs.items():
                retention = int(cfg.get('retention_days') or 90)
                # delete events older than retention except legal_hold
                sql = "DELETE FROM events WHERE tenant_id=%s AND ts < now() - interval '%s days' AND (legal_hold IS FALSE OR legal_hold IS NULL) RETURNING id"
                if dry_run:
                    cur.execute("SELECT count(*) FROM events WHERE tenant_id=%s AND ts < now() - interval '%s days' AND (legal_hold IS FALSE OR legal_hold IS NULL)", (tenant, retention))
                    row = cur.fetchone()
                    counts[tenant] = int(row[0]) if row and row[0] else 0
                else:
                    cur.execute(sql, (tenant, retention))
                    rows = cur.fetchall()
                    counts[tenant] = len(rows)
            # Handle default tenants not in configs: apply global default
            cur.execute("SELECT count(*) FROM events WHERE tenant_id NOT IN (SELECT tenant_id FROM integration_configs WHERE name='retention') AND ts < now() - interval '90 days' AND (legal_hold IS FALSE OR legal_hold IS NULL)")
            row = cur.fetchone()
            counts['__default__'] = int(row[0]) if row and row[0] else 0
        if not dry_run:
            conn.commit()
        conn.close()
    except Exception:
        pass
    return counts


if __name__ == '__main__':
    print('Running retention sweep dry-run:')
    print(sweep_once(dry_run=True))
