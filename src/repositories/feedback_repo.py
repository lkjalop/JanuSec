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


# --- Report feedback table & helpers (row-level LLM feedback)
CREATE_REPORT_FEEDBACK = """
CREATE TABLE IF NOT EXISTS report_feedback (
    id SERIAL PRIMARY KEY,
    report_id TEXT NOT NULL,
    row_id TEXT NOT NULL,
    org TEXT,
    accurate BOOLEAN,
    comment TEXT,
    reviewer TEXT,
    ts TIMESTAMP WITH TIME ZONE DEFAULT NOW()
)
"""

INSERT_REPORT_FEEDBACK = """
INSERT INTO report_feedback (report_id, row_id, org, accurate, comment, reviewer) VALUES ($1,$2,$3,$4,$5,$6)
"""

SELECT_REPORT_FEEDBACK = """
SELECT report_id, row_id, org, accurate, comment, reviewer, extract(epoch from ts) as ts FROM report_feedback WHERE report_id=$1 ORDER BY ts DESC
"""


async def ensure_report_feedback_table():
    try:
        await execute(CREATE_REPORT_FEEDBACK)
    except Exception:
        # best-effort
        pass


async def insert_report_feedback(report_id: str, row_id: str, org: str | None, accurate: bool, comment: str | None, reviewer: str | None):
    await ensure_report_feedback_table()
    return await execute(INSERT_REPORT_FEEDBACK, report_id, row_id, org, accurate, comment, reviewer)


async def get_feedback_for_report(report_id: str):
    await ensure_report_feedback_table()
    rows = await fetch(SELECT_REPORT_FEEDBACK, report_id)
    return [dict(r) for r in rows]


async def migrate_feedback_jsonl_to_db(base_dir: str):
    """Scan given base_dir for report feedback JSONL files and migrate them into DB.
    base_dir should be the path to data/assessments/{org} or higher.
    """
    import glob, json, os
    await ensure_report_feedback_table()
    migrated = 0
    for fb in glob.glob(os.path.join(base_dir, '**', 'reports', 'feedback_*.jsonl'), recursive=True):
        try:
            with open(fb, 'r', encoding='utf-8') as fh:
                for line in fh:
                    try:
                        j = json.loads(line)
                        rpt = j.get('report_id')
                        row = j.get('row_id')
                        org = j.get('org')
                        acc = bool(j.get('accurate'))
                        com = j.get('comment')
                        rev = j.get('reviewer')
                        await insert_report_feedback(rpt, row, org, acc, com, rev)
                        migrated += 1
                    except Exception:
                        continue
        except Exception:
            continue
    return migrated
