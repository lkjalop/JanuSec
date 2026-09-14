"""API Key Scoping & Rotation Helpers

Lightweight abstraction around `api_keys` table for multi-tenant isolation.
Supports:
 - Verification of active key and tenant alignment
 - Optional scope checking (comma-separated list in scopes column)
 - Rotation (disable old key, insert new)

Intended to be called early in request pipeline (dependency in FastAPI route)
before hitting tenant-scoped resources.
"""
from __future__ import annotations
import os, asyncio
from typing import Any, Optional
import logging
logger = logging.getLogger(__name__)

async def get_db_conn():  # minimal adapter access
    from database_adapter import db_manager
    adp = db_manager.adapter
    if not adp:
        await db_manager.initialize()
        adp = db_manager.adapter
    return adp

async def verify_api_key(api_key: str, tenant_id: Optional[str] = None, required_scopes: list[str] | None = None) -> bool:
    if not api_key:
        return False
    adp = await get_db_conn()
    if not adp:
        return False
    try:
        if hasattr(adp,'pool') and adp.pool:  # Postgres
            async with adp.pool.acquire() as conn:  # type: ignore[attr-defined]
                row = await conn.fetchrow("SELECT api_key, tenant_id, scopes, enabled FROM api_keys WHERE api_key=$1", api_key)
        elif hasattr(adp,'connection') and adp.connection:  # SQLite
            cur = await adp.connection.execute("SELECT api_key, tenant_id, scopes, enabled FROM api_keys WHERE api_key=?", (api_key,))  # type: ignore[attr-defined]
            row = await cur.fetchone()
            if row:
                row = {'api_key': row[0], 'tenant_id': row[1], 'scopes': row[2], 'enabled': row[3]}
        else:
            row = None
    except Exception as e:  # pragma: no cover
        logger.warning(f"API key lookup failed: {e}")
        return False
    if not row or not row.get('enabled'):
        return False
    if tenant_id and row.get('tenant_id') != tenant_id:
        return False
    if required_scopes:
        scopes_raw = row.get('scopes') or ''
        present = {s.strip() for s in scopes_raw.split(',') if s.strip()}
        if not all(s in present for s in required_scopes):
            return False
    # Update last_used_at (best-effort)
    try:
        if hasattr(adp,'pool') and adp.pool:
            async with adp.pool.acquire() as conn:  # type: ignore[attr-defined]
                await conn.execute("UPDATE api_keys SET last_used_at=NOW() WHERE api_key=$1", api_key)
        elif hasattr(adp,'connection') and adp.connection:
            await adp.connection.execute("UPDATE api_keys SET last_used_at=datetime('now') WHERE api_key=?", (api_key,))  # type: ignore[attr-defined]
            await adp.connection.commit()  # type: ignore[attr-defined]
    except Exception:
        pass
    return True

async def rotate_api_key(old_key: str, new_key: str, tenant_id: str, scopes: list[str] | None = None) -> bool:
    adp = await get_db_conn()
    if not adp:
        return False
    scopes_str = ','.join(scopes or [])
    try:
        if hasattr(adp,'pool') and adp.pool:
            async with adp.pool.acquire() as conn:  # type: ignore[attr-defined]
                await conn.execute("UPDATE api_keys SET enabled=FALSE WHERE api_key=$1", old_key)
                await conn.execute("INSERT INTO api_keys(api_key, tenant_id, scopes) VALUES($1,$2,$3)", new_key, tenant_id, scopes_str)
        elif hasattr(adp,'connection') and adp.connection:
            await adp.connection.execute("UPDATE api_keys SET enabled=0 WHERE api_key=?", (old_key,))  # type: ignore[attr-defined]
            await adp.connection.execute("INSERT INTO api_keys(api_key, tenant_id, scopes) VALUES(?,?,?)", (new_key, tenant_id, scopes_str))  # type: ignore[attr-defined]
            await adp.connection.commit()  # type: ignore[attr-defined]
        return True
    except Exception as e:
        logger.warning(f"API key rotation failed: {e}")
        return False

__all__ = ["verify_api_key","rotate_api_key"]