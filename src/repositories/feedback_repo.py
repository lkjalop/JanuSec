"""Repository for analyst factor feedback."""
from __future__ import annotations
from typing import Any, Dict, List
from db.database import execute, fetch, with_retry

INSERT = """
INSERT INTO factor_feedback (event_id, factor, vote, comment) VALUES ($1,$2,$3,$4)
"""

AGG_FACTOR = """
SELECT factor, sum(vote) AS score, count(*) AS total
FROM factor_feedback
GROUP BY factor
ORDER BY score DESC, total DESC
LIMIT $1
"""

async def insert_feedback(event_id: str, factor: str, vote: int, comment: str | None):
    async def _do():
        return await execute(INSERT, event_id, factor, vote, comment)
    return await with_retry(_do)

async def top_feedback(limit: int = 50):
    rows = await fetch(AGG_FACTOR, limit)
    return [dict(r) for r in rows]
