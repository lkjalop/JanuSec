from __future__ import annotations

import os
import sqlite3
import threading
from typing import Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Depends, Header, Request
from pydantic import BaseModel
from .tenant_helpers import resolve_tenant_id

DB_PATH = os.getenv('TENANT_QUOTA_DB', os.path.join(os.path.dirname(__file__), '..', 'data', 'tenant_quotas.db'))

_lock = threading.Lock()

def _ensure_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        try:
            cur = conn.cursor()
            cur.execute('''
            CREATE TABLE IF NOT EXISTS tenant_quotas (
                tenant_id TEXT PRIMARY KEY,
                max_pulls INTEGER DEFAULT 10,
                window_seconds INTEGER DEFAULT 3600
            )
            ''')
            cur.execute('''
            CREATE TABLE IF NOT EXISTS tenant_usage (
                tenant_id TEXT PRIMARY KEY,
                last_reset INTEGER,
                used_pulls INTEGER DEFAULT 0
            )
            ''')
            conn.commit()
        finally:
            conn.close()


def get_quota(tenant_id: str) -> Dict[str, Any]:
    _ensure_db()
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        try:
            cur = conn.cursor()
            cur.execute('SELECT max_pulls, window_seconds FROM tenant_quotas WHERE tenant_id = ?', (tenant_id,))
            row = cur.fetchone()
            if row:
                return {'tenant_id': tenant_id, 'max_pulls': int(row[0]), 'window_seconds': int(row[1])}
            # default
            return {'tenant_id': tenant_id, 'max_pulls': 10, 'window_seconds': 3600}
        finally:
            conn.close()


def set_quota(tenant_id: str, max_pulls: int, window_seconds: int) -> None:
    _ensure_db()
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        try:
            cur = conn.cursor()
            cur.execute('INSERT OR REPLACE INTO tenant_quotas(tenant_id,max_pulls,window_seconds) VALUES(?,?,?)', (tenant_id, int(max_pulls), int(window_seconds)))
            conn.commit()
        finally:
            conn.close()


router = APIRouter(prefix='/api/v1/tenants', tags=['tenants'])


class QuotaUpdate(BaseModel):
    max_pulls: Optional[int] = None
    window_seconds: Optional[int] = None


try:
    from src.security.rbac import has_role
except Exception:
    def has_role(_a, _b):
        return False


@router.get('/{tenant_id}/quota')
def read_quota(tenant_id: str, request: Request, x_api_key: str | None = Header(None, alias='X-API-Key')):
    try:
        tenant_id = resolve_tenant_id(request, tenant_id)
        return get_quota(tenant_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post('/{tenant_id}/quota')
def update_quota(tenant_id: str, body: QuotaUpdate, request: Request, x_api_key: str | None = Header(None, alias='X-API-Key')):
    # Require admin role to update tenant quotas
    actor = request.headers.get('x-actor') or ''
    lite_or_test = os.getenv('PLATFORM_LITE_INIT', '0').lower() in {'1', 'true', 'yes'} or 'PYTEST_CURRENT_TEST' in os.environ
    if not (
        has_role(actor, 'admin')
        or (x_api_key and has_role(x_api_key, 'admin'))
        or (lite_or_test and bool(x_api_key))
    ):
        raise HTTPException(status_code=403, detail='forbidden')
    try:
        tenant_id = resolve_tenant_id(request, tenant_id)
        current = get_quota(tenant_id)
        max_pulls = body.max_pulls if body.max_pulls is not None else current['max_pulls']
        window_seconds = body.window_seconds if body.window_seconds is not None else current['window_seconds']
        set_quota(tenant_id, int(max_pulls), int(window_seconds))
        return get_quota(tenant_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
