from fastapi import APIRouter, Query
import aiosqlite
from typing import List

router = APIRouter(prefix='/api/v1/precision')


@router.get('/daily')
async def get_daily(rule_id: str | None = Query(None), days: int = Query(7)):
    db = 'data/app.db'
    q = 'SELECT day, rule_id, ab_variant, tp, fp FROM precision_daily'
    params = []
    if rule_id:
        q += ' WHERE rule_id = ?'
        params.append(rule_id)
    q += ' ORDER BY day DESC LIMIT ?'
    params.append(days)
    rows = []
    async with aiosqlite.connect(db) as conn:
        cur = await conn.execute(q, params)
        for r in await cur.fetchall():
            rows.append({'day': r[0], 'rule_id': r[1], 'ab_variant': r[2], 'tp': r[3], 'fp': r[4]})
    return {'rows': rows}
