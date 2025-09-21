"""Access log repository"""
from __future__ import annotations
from typing import List, Dict, Any
from db.database import execute, with_retry

INSERT = """
INSERT INTO access_log(subject, method, path, status, scopes, ip, user_agent)
VALUES ($1,$2,$3,$4,$5,$6,$7)
"""

async def record(subject: str, method: str, path: str, status: int, scopes: List[str], ip: str | None, ua: str | None):
    async def _do():
        return await execute(INSERT, subject, method, path, status, scopes, ip, ua)
    return await with_retry(_do)
