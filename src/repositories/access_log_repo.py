"""Access log repository"""
from __future__ import annotations
from typing import List, Dict, Any
from db.database import execute, with_retry

INSERT = """
INSERT INTO access_log(subject, method, path, status, scopes, ip, user_agent, tenant_id)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
"""

async def record(subject: str, method: str, path: str, status: int, scopes: List[str], ip: str | None, ua: str | None, tenant_id: str | None):
    async def _do():
        return await execute(INSERT, subject, method, path, status, scopes, ip, ua, tenant_id)
    return await with_retry(_do)
