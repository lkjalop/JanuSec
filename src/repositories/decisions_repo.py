"""Decisions Repository"""
from __future__ import annotations
import json
from typing import Any, Dict, Optional
from db.database import execute, fetchrow, fetch, with_retry

INSERT_DECISION = """
INSERT INTO decisions (event_id, verdict, confidence, processing_ms, factors, stage_timings, custody_hash)
VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7)
ON CONFLICT (event_id) DO UPDATE SET
    verdict=EXCLUDED.verdict,
    confidence=EXCLUDED.confidence,
    processing_ms=EXCLUDED.processing_ms,
    factors=EXCLUDED.factors,
    stage_timings=EXCLUDED.stage_timings,
    custody_hash=EXCLUDED.custody_hash
"""

GET_DECISION = "SELECT * FROM decisions WHERE event_id=$1"
LIST_RECENT = "SELECT * FROM decisions ORDER BY created_at DESC LIMIT $1"

async def upsert_decision(event_id: str, decision: Any):
    factors_json = json.dumps(decision.factors)
    stage_timings_json = json.dumps(decision.stage_timings)
    async def _do():
        return await execute(
            INSERT_DECISION,
            event_id,
            decision.verdict,
            float(decision.confidence),
            float(decision.processing_time_ms),
            factors_json,
            stage_timings_json,
            decision.custody_hash
        )
    return await with_retry(_do)

async def get_decision(event_id: str) -> Optional[Dict[str, Any]]:
    row = await fetchrow(GET_DECISION, event_id)
    return dict(row) if row else None

async def list_recent(limit: int = 50):
    rows = await fetch(LIST_RECENT, limit)
    return [dict(r) for r in rows]
