"""Repository for aggregated factor weights derived from feedback."""
from __future__ import annotations

from typing import Any, Dict

from db.database import execute, fetch, with_retry

UPSERT = """
INSERT INTO factor_weights (factor, weight, last_updated, tenant_id)
VALUES ($1,$2,NOW(),$3)
ON CONFLICT (factor) DO UPDATE SET weight=EXCLUDED.weight, last_updated=NOW()
"""

SELECT_ALL = "SELECT factor, weight FROM factor_weights WHERE (tenant_id=$1 OR (tenant_id IS NULL AND $1 IS NULL))"
SELECT_DETAILED = """
SELECT factor, weight, last_updated
FROM factor_weights
WHERE (tenant_id=$1 OR (tenant_id IS NULL AND $1 IS NULL))
"""

async def upsert_factor_weight(factor: str, weight: float, tenant_id: str | None):
    async def _do():
        return await execute(UPSERT, factor, weight, tenant_id)
    return await with_retry(_do)

async def load_weights(tenant_id: str | None = None) -> dict[str,float]:
    rows = await fetch(SELECT_ALL, tenant_id)
    return {r['factor']: r['weight'] for r in rows}

async def load_weights_detailed(tenant_id: str | None = None):
    rows = await fetch(SELECT_DETAILED, tenant_id)
    return [dict(r) for r in rows]
