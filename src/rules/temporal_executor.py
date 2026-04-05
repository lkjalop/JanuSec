from __future__ import annotations
"""Temporal executor utilities: sequence, absence, rate, zscore.

These functions query the events table to perform windowed evaluations.
They are intentionally minimal and synchronous for easy testing; they can be
rewritten to async DB calls and optimized with indices later.
"""
import time
from typing import List, Dict, Any
import psycopg2
import os

DB_DSN = os.getenv('JNS_DB_DSN', 'postgresql://postgres:postgres@localhost:5432/janusec')


def _get_conn():
    return psycopg2.connect(DB_DSN)


def execute_sequence(steps: List[Dict[str, Any]], window_seconds: int, tenant_id: str = 'default') -> bool:
    """Steps: list of Comparison AST nodes with field/op/value

    Query events for tenant in window and check ordered occurrence of step predicates.
    """
    # Build simple SQL to fetch recent events for tenant ordered by ts
    try:
        conn = _get_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT id, raw, extract(epoch from ts) as ets FROM events WHERE tenant_id=%s AND ts >= now() - interval '%s seconds' ORDER BY ts ASC", (tenant_id, window_seconds))
            rows = cur.fetchall()
        conn.close()
    except Exception:
        return False
    # Convert rows to list of raw dicts
    observed = [r[1] for r in rows if r and r[1]]
    # Evaluate each step against observed sequence
    idx = 0
    for step in steps:
        # step is Comparison AST; we evaluate by simple field comparisons
        found = False
        for i, ev in enumerate(observed[idx:], start=idx):
            try:
                # evaluate step
                lhs = _get_field(ev, step.field)
                if lhs is None:
                    continue
                op = step.op
                rhs = step.value
                if _cmp(lhs, op, rhs):
                    found = True
                    # advance search index to after matched event
                    idx = i + 1
                    break
            except Exception:
                continue
        if not found:
            return False
        # advance idx to position after found event
        # naive: we don't track index positions; keep scanning
    return True


def execute_absence(predicate, window_seconds: int, tenant_id: str = 'default') -> bool:
    # predicate is Comparison AST
    try:
        conn = _get_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT raw FROM events WHERE tenant_id=%s AND ts >= now() - interval '%s seconds'", (tenant_id, window_seconds))
            rows = cur.fetchall()
        conn.close()
    except Exception:
        return False
    for r in rows:
        try:
            ev = r[0]
            lhs = _get_field(ev, predicate.field)
            if lhs is None:
                continue
            if _cmp(lhs, predicate.op, predicate.value):
                return False
        except Exception:
            continue
    return True


def evaluate_rate(field: List[str], window_seconds: int, op: str, threshold: float, tenant_id: str = 'default') -> bool:
    fld = '.'.join(field)
    try:
        conn = _get_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM events WHERE tenant_id=%s AND (raw->%s) IS NOT NULL AND ts >= now() - interval '%s seconds'", (tenant_id, fld, window_seconds))
            row = cur.fetchone()
        conn.close()
        cnt = int(row[0]) if row and row[0] else 0
        return _cmp(cnt, op, threshold)
    except Exception:
        return False


def evaluate_zscore(field: List[str], window_seconds: int, op: str, threshold: float, tenant_id: str = 'default') -> bool:
    # Basic placeholder: compute mean/std over the window and compare zscore of latest value
    fld = '.'.join(field)
    try:
        conn = _get_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT (raw->>%s)::float FROM events WHERE tenant_id=%s AND ts >= now() - interval '%s seconds'", (fld, tenant_id, window_seconds))
            rows = cur.fetchall()
        conn.close()
        vals = [float(r[0]) for r in rows if r and r[0] is not None]
        if not vals:
            return False
        import statistics
        mean = statistics.mean(vals)
        stdev = statistics.pstdev(vals) if len(vals) > 1 else 0.0
        latest = vals[-1]
        if stdev == 0:
            return False
        z = (latest - mean) / stdev
        return _cmp(z, op, threshold)
    except Exception:
        return False


# Simple helpers (copied from dsl_parser helpers)
from src.rules.dsl_parser import _get_field, _cmp


# ---------------- Async / optimized variants (experimental) ----------------
import asyncio

async def async_execute_sequence(steps: List[Dict[str, Any]], window_seconds: int, tenant_id: str = 'default') -> bool:
    # Async wrapper that runs blocking DB call in threadpool
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, execute_sequence, steps, window_seconds, tenant_id)

async def async_execute_absence(predicate, window_seconds: int, tenant_id: str = 'default') -> bool:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, execute_absence, predicate, window_seconds, tenant_id)

async def async_evaluate_rate(field: List[str], window_seconds: int, op: str, threshold: float, tenant_id: str = 'default') -> bool:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, evaluate_rate, field, window_seconds, op, threshold, tenant_id)

async def async_evaluate_zscore(field: List[str], window_seconds: int, op: str, threshold: float, tenant_id: str = 'default') -> bool:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, evaluate_zscore, field, window_seconds, op, threshold, tenant_id)