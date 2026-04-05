from __future__ import annotations

"""Secure token store with best-effort encryption.

Falls back to in-memory when DB or cryptography are unavailable. Designed to
avoid breaking tests or lightweight runs while providing a clear upgrade path
to Vault/KMS-backed storage.
"""

import base64
import json
import logging
import os
import time
from datetime import datetime
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

try:
    from cryptography.fernet import Fernet  # type: ignore
except Exception:
    Fernet = None  # type: ignore


class TokenStore:
    def __init__(self, encryption_key: Optional[bytes] = None):
        self._mem: Dict[str, Dict[str, Any]] = {}
        self._cipher = None
        if Fernet is not None:
            try:
                self._cipher = Fernet(encryption_key or Fernet.generate_key())
            except Exception:
                self._cipher = None
        # DB usage is optional and gated; default to enabled when DB is available
        self._use_db = os.getenv('TOKEN_STORE_DB', '1').lower() in {'1', 'true', 'yes'}
        self._db_ready_checked = False

    def _enc(self, obj: Dict[str, Any]) -> bytes:
        raw = json.dumps(obj).encode('utf-8')
        if self._cipher:
            try:
                return self._cipher.encrypt(raw)
            except Exception:
                pass
        return base64.b64encode(raw)

    def _dec(self, blob: bytes) -> Dict[str, Any]:
        data = blob
        if self._cipher:
            try:
                data = self._cipher.decrypt(blob)
            except Exception:
                # fallback to base64 decode
                try:
                    data = base64.b64decode(blob)
                except Exception:
                    data = b"{}"
        else:
            try:
                data = base64.b64decode(blob)
            except Exception:
                pass
        try:
            return json.loads(data.decode('utf-8') or '{}')
        except Exception:
            return {}

    async def store_token(self, tenant_id: str, provider: str, token_data: Dict[str, Any], expiry: datetime) -> None:
        blob = self._enc(token_data)
        if await self._try_store_db(tenant_id, provider, blob, expiry):
            logger.info("Stored token (db) for %s provider=%s", tenant_id, provider)
            return
        # Fallback to in-memory
        key = f"{tenant_id}:{provider}"
        self._mem[key] = {
            'blob': blob,
            'expiry': expiry,
        }
        logger.info("Stored token (mem) for %s provider=%s expiry=%s", tenant_id, provider, expiry.isoformat())

    async def get_token(self, tenant_id: str, provider: str) -> Optional[Dict[str, Any]]:
        # Attempt DB first when available
        got = await self._try_get_db(tenant_id, provider)
        if got is not None:
            return got
        # Fallback to in-memory
        key = f"{tenant_id}:{provider}"
        rec = self._mem.get(key)
        if not rec:
            return None
        try:
            if datetime.utcnow() >= (rec.get('expiry') or datetime.utcnow()):
                # expired
                self._mem.pop(key, None)
                return None
        except Exception:
            pass
        return self._dec(rec.get('blob') or b"{}")

    async def revoke_token(self, tenant_id: str, provider: str) -> None:
        if await self._try_revoke_db(tenant_id, provider):
            logger.info("Revoked token (db) for %s provider=%s", tenant_id, provider)
            return
        key = f"{tenant_id}:{provider}"
        self._mem.pop(key, None)
        logger.info("Revoked token (mem) for %s provider=%s", tenant_id, provider)

    async def _ensure_db_ready(self) -> bool:
        """Best-effort check and table create when DB is enabled.
        Avoids raising when DB not configured; returns False in that case.
        """
        if not self._use_db:
            return False
        try:
            from src.db import database as db  # type: ignore
        except Exception:
            try:
                import db.database as db  # type: ignore
            except Exception:
                return False
        # Verify pool and create table if needed (idempotent)
        try:
            pool = await db.get_pool()
        except Exception:
            return False
        # Only ensure once per process
        if self._db_ready_checked:
            return True
        try:
            # DDL compatible with both backends
            create_sql = (
                """
                CREATE TABLE IF NOT EXISTS oauth_tokens (
                    tenant_id TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    blob TEXT NOT NULL,
                    expiry REAL NOT NULL,
                    updated_at REAL,
                    PRIMARY KEY (tenant_id, provider)
                )
                """
            )
            await db.execute(create_sql)
            self._db_ready_checked = True
            return True
        except Exception:
            # If table creation fails, continue in-memory without crashing
            return False

    async def _try_store_db(self, tenant_id: str, provider: str, blob: bytes, expiry: datetime) -> bool:
        if not await self._ensure_db_ready():
            return False
        try:
            from src.db import database as db  # type: ignore
        except Exception:
            try:
                import db.database as db  # type: ignore
            except Exception:
                return False
        try:
            # Use backend-appropriate placeholder style
            now_epoch = time.time()
            blob_text = blob.decode('utf-8') if isinstance(blob, (bytes, bytearray)) else str(blob)
            expiry_ts = float(expiry.timestamp())
            if db.is_fallback_active():
                sql = (
                    "INSERT INTO oauth_tokens (tenant_id, provider, blob, expiry, updated_at) "
                    "VALUES (?,?,?,?,?) ON CONFLICT(tenant_id, provider) DO UPDATE SET "
                    "blob=excluded.blob, expiry=excluded.expiry, updated_at=excluded.updated_at"
                )
                await db.execute(sql, tenant_id, provider, blob_text, expiry_ts, now_epoch)
            else:
                sql = (
                    "INSERT INTO oauth_tokens (tenant_id, provider, blob, expiry, updated_at) "
                    "VALUES ($1,$2,$3,$4,$5) ON CONFLICT(tenant_id, provider) DO UPDATE SET "
                    "blob=EXCLUDED.blob, expiry=EXCLUDED.expiry, updated_at=EXCLUDED.updated_at"
                )
                await db.execute(sql, tenant_id, provider, blob_text, expiry_ts, now_epoch)
            return True
        except Exception as exc:
            logger.debug("TokenStore DB store failed: %s", str(exc).split('\n',1)[0])
            return False

    async def _try_get_db(self, tenant_id: str, provider: str) -> Optional[Dict[str, Any]]:
        if not await self._ensure_db_ready():
            return None
        try:
            from src.db import database as db  # type: ignore
        except Exception:
            try:
                import db.database as db  # type: ignore
            except Exception:
                return None
        try:
            if db.is_fallback_active():
                row = await db.fetchrow(
                    "SELECT blob, expiry FROM oauth_tokens WHERE tenant_id = ? AND provider = ?",
                    tenant_id, provider
                )
            else:
                row = await db.fetchrow(
                    "SELECT blob, expiry FROM oauth_tokens WHERE tenant_id = $1 AND provider = $2",
                    tenant_id, provider
                )
            if not row:
                return None
            expiry_ts = float(row.get('expiry') or 0)
            if time.time() >= expiry_ts:
                # Soft-expired; do not return
                return None
            blob_text = row.get('blob') or ''
            try:
                blob_bytes = blob_text.encode('utf-8')
            except Exception:
                blob_bytes = b"{}"
            return self._dec(blob_bytes)
        except Exception as exc:
            logger.debug("TokenStore DB get failed: %s", str(exc).split('\n',1)[0])
            return None

    async def _try_revoke_db(self, tenant_id: str, provider: str) -> bool:
        if not await self._ensure_db_ready():
            return False
        try:
            from src.db import database as db  # type: ignore
        except Exception:
            try:
                import db.database as db  # type: ignore
            except Exception:
                return False
        try:
            if db.is_fallback_active():
                sql = "DELETE FROM oauth_tokens WHERE tenant_id = ? AND provider = ?"
                await db.execute(sql, tenant_id, provider)
            else:
                sql = "DELETE FROM oauth_tokens WHERE tenant_id = $1 AND provider = $2"
                await db.execute(sql, tenant_id, provider)
            return True
        except Exception as exc:
            logger.debug("TokenStore DB revoke failed: %s", str(exc).split('\n',1)[0])
            return False


    async def list_tokens(self) -> list[Dict[str, Any]]:
        """Return metadata for stored OAuth tokens."""
        items: list[Dict[str, Any]] = []
        if await self._ensure_db_ready():
            try:
                from src.db import database as db  # type: ignore
            except Exception:
                try:
                    import db.database as db  # type: ignore
                except Exception:
                    db = None  # type: ignore
            if db is not None:
                try:
                    rows = await db.fetch("SELECT tenant_id, provider, expiry FROM oauth_tokens")
                    for record in rows or []:
                        try:
                            items.append(
                                {
                                    'tenant_id': record.get('tenant_id'),
                                    'provider': record.get('provider'),
                                    'expiry': float(record.get('expiry') or 0.0),
                                }
                            )
                        except Exception:
                            continue
                    return items
                except Exception:
                    pass
        for key, value in self._mem.items():
            try:
                tenant_id, provider = key.split(':', 1)
            except Exception:
                continue
            try:
                expiry_val = value.get('expiry')
                expiry_ts = float(expiry_val.timestamp()) if isinstance(expiry_val, datetime) else 0.0
            except Exception:
                expiry_ts = 0.0
            items.append({'tenant_id': tenant_id, 'provider': provider, 'expiry': expiry_ts})
        return items


__all__ = ["TokenStore"]
