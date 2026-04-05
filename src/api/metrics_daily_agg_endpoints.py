from __future__ import annotations

import os
import sqlite3
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Query

DB_PATH = os.getenv('JANUSEC_SQLITE_PATH', 'data/janusec.db')

router = APIRouter(prefix='/api/v1/metrics', tags=['daily-agg'])


def _conn() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@router.get('/daily_precision')
def daily_precision(
    start_ts: int = Query(..., description='UTC start timestamp (00:00 boundary recommended)'),
    end_ts: int = Query(..., description='UTC end timestamp (exclusive)'),
    rule_id: Optional[str] = Query(None),
    ab_variant: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """Return aggregated daily TP/FP counts and precision from the precision_daily table.

    Source: populated by PrecisionAggregator.aggregate_day
    """
    try:
        with _conn() as conn:
            params: List[Any] = []
            where = ['day >= ?', 'day < ?']
            params.extend([start_ts, end_ts])
            if rule_id:
                where.append('rule_id = ?')
                params.append(rule_id)
            if ab_variant:
                where.append('ab_variant = ?')
                params.append(ab_variant)
            sql = (
                'SELECT day, rule_id, ab_variant, tp, fp '
                'FROM precision_daily WHERE ' + ' AND '.join(where) + ' '
                'ORDER BY day ASC'
            )
            cur = conn.execute(sql, params)
            rows = cur.fetchall()
        series: List[Dict[str, Any]] = []
        for r in rows:
            tp = int(r['tp'] or 0)
            fp = int(r['fp'] or 0)
            total = tp + fp
            series.append({
                'day_ts': int(r['day']),
                'rule_id': r['rule_id'],
                'ab_variant': r['ab_variant'] or 'control',
                'tp': tp,
                'fp': fp,
                'total': total,
                'precision': (tp / total) if total > 0 else None,
            })
        return {'start_ts': start_ts, 'end_ts': end_ts, 'series': series}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get('/daily_precision/by_rule')
def daily_precision_by_rule(
    start_ts: int = Query(...),
    end_ts: int = Query(...),
) -> Dict[str, Any]:
    """Return a grouped view keyed by rule_id with daily series for convenience."""
    try:
        with _conn() as conn:
            cur = conn.execute(
                'SELECT day, rule_id, ab_variant, tp, fp FROM precision_daily WHERE day >= ? AND day < ? ORDER BY day ASC, rule_id',
                (start_ts, end_ts),
            )
            rows = cur.fetchall()
        out: Dict[str, List[Dict[str, Any]]] = {}
        for r in rows:
            rid = r['rule_id']
            tp = int(r['tp'] or 0)
            fp = int(r['fp'] or 0)
            total = tp + fp
            rec = {
                'day_ts': int(r['day']),
                'ab_variant': r['ab_variant'] or 'control',
                'tp': tp,
                'fp': fp,
                'total': total,
                'precision': (tp / total) if total > 0 else None,
            }
            out.setdefault(rid, []).append(rec)
        return {'start_ts': start_ts, 'end_ts': end_ts, 'by_rule': out}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
