"""Repository for analyst factor feedback."""
from __future__ import annotations
from typing import Any, Dict, List
from db.database import execute, fetch, with_retry

INSERT = """
INSERT INTO factor_feedback (event_id, factor, vote, comment, tenant_id) VALUES ($1,$2,$3,$4,$5)
"""

AGG_FACTOR = """
SELECT factor, sum(vote) AS score, count(*) AS total
FROM factor_feedback
GROUP BY factor
ORDER BY score DESC, total DESC
LIMIT $1
"""

AGG_WINDOW = """
SELECT factor,
             sum(CASE WHEN vote=1 THEN 1 ELSE 0 END) AS up_votes,
             sum(CASE WHEN vote=-1 THEN 1 ELSE 0 END) AS down_votes,
             sum(vote) AS net,
             count(*) AS total
FROM factor_feedback
WHERE created_at >= (NOW() - $1::interval)
    AND (tenant_id=$2 OR (tenant_id IS NULL AND $2 IS NULL))
GROUP BY factor
ORDER BY net DESC, total DESC
LIMIT $3
"""

async def insert_feedback(event_id: str, factor: str, vote: int, comment: str | None, tenant_id: str | None):
    async def _do():
        return await execute(INSERT, event_id, factor, vote, comment, tenant_id)
    return await with_retry(_do)

async def top_feedback(limit: int = 50):
    rows = await fetch(AGG_FACTOR, limit)
    return [dict(r) for r in rows]

async def aggregate_votes(window: str, tenant_id: str | None, limit: int = 100):
    """Aggregate votes in a rolling window (e.g. '30 days', '7 days', '24 hours')."""
    rows = await fetch(AGG_WINDOW, window, tenant_id, limit)
    return [dict(r) for r in rows]
