"""Repository for aggregated factor weights derived from feedback."""
from __future__ import annotations
from typing import Dict, Any
from db.database import fetch, execute, with_retry

UPSERT = """
INSERT INTO factor_weights (factor, weight, last_updated)
VALUES ($1,$2,NOW())
ON CONFLICT (factor) DO UPDATE SET weight=EXCLUDED.weight, last_updated=NOW()
"""

SELECT_ALL = "SELECT factor, weight FROM factor_weights"

async def upsert_factor_weight(factor: str, weight: float):
    async def _do():
        return await execute(UPSERT, factor, weight)
    return await with_retry(_do)

async def load_weights() -> Dict[str,float]:
    rows = await fetch(SELECT_ALL)
    return {r['factor']: r['weight'] for r in rows}
