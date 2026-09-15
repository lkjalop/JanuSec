from __future__ import annotations
from typing import Optional, List, Dict
from db.database import execute, fetch

INSERT_LABEL = """
INSERT INTO decision_labels (event_id, decision_id, label, tenant_id, test_id, variant, evidence, query_template)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
"""

AGG_DAILY = """
SELECT date_trunc('day', created_at) AS day,
       SUM(CASE WHEN label='true_positive' THEN 1 ELSE 0 END) AS tp,
       SUM(CASE WHEN label='false_positive' THEN 1 ELSE 0 END) AS fp,
       SUM(CASE WHEN label='false_negative' THEN 1 ELSE 0 END) AS fn
FROM decision_labels
WHERE (tenant_id=$1 OR (tenant_id IS NULL AND $1 IS NULL))
  AND created_at >= $2::timestamptz
  AND created_at < $3::timestamptz
GROUP BY day
ORDER BY day ASC
"""

AGG_AB_TEST = """
SELECT variant, SUM(CASE WHEN label='true_positive' THEN 1 ELSE 0 END) AS tp,
       SUM(CASE WHEN label='false_positive' THEN 1 ELSE 0 END) AS fp,
       SUM(CASE WHEN label='false_negative' THEN 1 ELSE 0 END) AS fn
FROM decision_labels
WHERE (tenant_id=$1 OR (tenant_id IS NULL AND $1 IS NULL))
  AND test_id=$2
GROUP BY variant
"""

AGG_AB_TEST_DAILY = """
SELECT date_trunc('day', created_at) AS day, variant,
       SUM(CASE WHEN label='true_positive' THEN 1 ELSE 0 END) AS tp,
       SUM(CASE WHEN label='false_positive' THEN 1 ELSE 0 END) AS fp,
       SUM(CASE WHEN label='false_negative' THEN 1 ELSE 0 END) AS fn
FROM decision_labels
WHERE (tenant_id=$1 OR (tenant_id IS NULL AND $1 IS NULL))
  AND test_id=$2
  AND created_at >= $3::timestamptz
  AND created_at < $4::timestamptz
GROUP BY day, variant
ORDER BY day ASC
"""


async def insert_label(event_id: str, decision_id: Optional[str], label: str, tenant_id: Optional[str], test_id: Optional[str]=None, variant: Optional[str]=None, evidence: Optional[str]=None, query_template: Optional[str]=None):
  # Best-effort: attempt to write to extended schema (evidence, query_template).
  try:
    return await execute(INSERT_LABEL, event_id, decision_id, label, tenant_id, test_id, variant, evidence, query_template)
  except Exception:
    # Fallback to legacy insert (graceful when running older DB schema in tests)
    try:
      from db.database import execute as _exec
      LEGACY = """
      INSERT INTO decision_labels (event_id, decision_id, label, tenant_id, test_id, variant)
      VALUES ($1,$2,$3,$4,$5,$6)
      """
      return await _exec(LEGACY, event_id, decision_id, label, tenant_id, test_id, variant)
    except Exception:
      raise


async def aggregate_daily(tenant_id: Optional[str], start_ts: str, end_ts: str) -> List[Dict]:
    rows = await fetch(AGG_DAILY, tenant_id, start_ts, end_ts)
    return [dict(r) for r in rows]


async def ab_test_summary(tenant_id: Optional[str], test_id: str) -> List[Dict]:
    rows = await fetch(AGG_AB_TEST, tenant_id, test_id)
    return [dict(r) for r in rows]


async def ab_test_daily(tenant_id: Optional[str], test_id: str, start_ts: str, end_ts: str) -> List[Dict]:
  rows = await fetch(AGG_AB_TEST_DAILY, tenant_id, test_id, start_ts, end_ts)
  return [dict(r) for r in rows]
