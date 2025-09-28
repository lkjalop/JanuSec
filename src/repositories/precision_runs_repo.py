"""Repository for precision evaluation runs."""
from __future__ import annotations
from typing import Any, Dict, List
from db.database import fetch, with_retry

INSERT = """
INSERT INTO precision_runs (threshold,tp,fp,tn,fn,precision,recall,f1,source_file)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
RETURNING id, created_at
"""

RECENT = """
SELECT id, created_at, threshold,tp,fp,tn,fn,precision,recall,f1,source_file
FROM precision_runs
ORDER BY created_at DESC
LIMIT $1
"""

async def insert_run(run: Dict[str, Any]):
    async def _do():
        return await fetch(INSERT, run['threshold'], run['counts']['tp'], run['counts']['fp'], run['counts']['tn'], run['counts']['fn'], run['precision'], run['recall'], run['f1'], run.get('source_file'))
    row = await with_retry(_do)
    return dict(row) if row else None

async def list_recent(limit: int = 50) -> List[Dict[str, Any]]:
    rows = await fetch(RECENT, limit)
    return [dict(r) for r in rows]

__all__ = ['insert_run','list_recent']
