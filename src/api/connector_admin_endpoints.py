from __future__ import annotations

import os
from typing import Any, Dict, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from pydantic import BaseModel

from src.connectors.registry import load_policies, save_policies, set_policy, get_policy, is_enabled
from src.security.roles import require_roles
try:
    from src.security.auth import require_scopes  # type: ignore
except Exception:  # pragma: no cover
    def require_scopes(*_scopes: str):  # type: ignore
        async def _noop():
            return None
        return _noop
try:
    from src.security.crypto_utils import encrypt_secret, decrypt_secret  # type: ignore
except Exception:
    encrypt_secret = decrypt_secret = None  # type: ignore
import json
from pathlib import Path

router = APIRouter(prefix="/api/v1/admin/connectors", tags=["admin-connectors"]) 


class ConnectorPolicy(BaseModel):
    enabled: bool = True
    rate_limit: Dict[str, float] | None = None  # {rate_per_second, burst}
    cost_cap_usd: float | None = None
    allow_hosts: list[str] | None = None


@router.get("/policies")
async def list_policies(auth: object = Depends(require_scopes('admin'))) -> Dict[str, Any]:
    pol = load_policies()
    return {"count": len(pol), "policies": pol}


@router.get("/policies/{name}")
async def get_policy_route(name: str, auth: object = Depends(require_scopes('admin'))) -> Dict[str, Any]:
    return {"name": name, "policy": get_policy(name), "enabled": is_enabled(name)}


@router.post("/policies/{name}")
async def update_policy(name: str, body: ConnectorPolicy, auth: object = Depends(require_scopes('admin'))) -> Dict[str, Any]:
    set_policy(name, body.model_dump())
    return {"updated": name}


# ---------------- Secrets storage (encrypted) ----------------
import logging
_LOGGER = logging.getLogger(__name__)

def _secrets_path() -> Path:
    """Resolve the secrets path at call time so tests can set env vars before use.

    This avoids capturing the environment at import time which can lead to
    different tests observing different paths depending on import ordering.
    """
    return Path(os.environ.get('CONNECTORS_SECRETS_PATH', 'data/connectors_secrets.json')).expanduser()


def _load_secrets() -> Dict[str, Dict[str, str]]:
    p = _secrets_path()
    try:
        if p.exists():
            with p.open('r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
    except Exception:
        _LOGGER.exception('Failed to load secrets from %s', p)
    return {}


def _save_secrets(obj: Dict[str, Dict[str, str]]) -> None:
    p = _secrets_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        # Write atomically to avoid corrupt files if process is killed
        tmp_path = p.with_suffix('.tmp')
        try:
            with tmp_path.open('w', encoding='utf-8') as f:
                json.dump(obj, f, indent=2)
                f.flush()
                try:
                    import os as _os
                    _os.fsync(f.fileno())
                except Exception:
                    # best-effort fsync
                    pass
            # Replace atomically
            tmp_path.replace(p)
        finally:
            try:
                if tmp_path.exists():
                    tmp_path.unlink()
            except Exception:
                pass
    except Exception as exc:
        _LOGGER.exception('Failed to save secrets to %s: %s', p, exc)
        # Surface error so tests will fail deterministically rather than silently
        raise

# Backwards-compatible alias: some tests import _SECRETS_PATH directly.
# Keep a snapshot at import time to avoid breaking those tests.
_SECRETS_PATH = _secrets_path()

@router.get("/secrets/{name}")
async def get_secrets(name: str, auth: object = Depends(require_scopes('admin'))) -> Dict[str, Any]:
    data = _load_secrets().get(name) or {}
    # Redact values while indicating presence
    redacted = {k: ('***' if isinstance(v, str) and v else None) for k, v in data.items()}
    return {"name": name, "secrets": redacted}


class SecretsBody(BaseModel):
    values: Dict[str, str]

@router.post("/secrets/{name}")
async def set_secrets(name: str, body: SecretsBody, request: Request, auth: object = Depends(require_scopes('admin'))) -> Dict[str, Any]:
    vals = body.values or {}
    if not isinstance(vals, dict):
        raise HTTPException(status_code=400, detail='invalid_body')
    cur = _load_secrets()
    encd: Dict[str, str] = {}
    for k, v in vals.items():
        if not isinstance(k, str):
            continue
        s = v if isinstance(v, str) else str(v)
        if encrypt_secret and os.getenv('ALLOW_INSECURE_FALLBACK','0').lower() not in {'1','true','yes'}:
            try:
                encd[k] = encrypt_secret(s)
            except Exception:
                # fallback to plain if encryption fails and dev fallback enabled
                encd[k] = s
        else:
            encd[k] = s
    cur[name] = encd
    _save_secrets(cur)
    return {"saved": True, "name": name, "keys": list(encd.keys())}


# ---------------- Config endpoints (non-secret) ----------------
class ConfigBody(BaseModel):
    config: Dict[str, Any]


def _normalize_config_body(body: Any) -> Dict[str, Any]:
    if isinstance(body, ConfigBody):
        return dict(body.config or {})
    if isinstance(body, dict):
        cfg = body.get('config')
        if isinstance(cfg, dict):
            return dict(cfg)
        return dict(body)
    return {}


@router.get("/config/{name}")
async def get_config_route(name: str, auth: object = Depends(require_scopes('admin'))):
    try:
        from src.connectors.registry import get_config
        cfg = get_config(name) or {}
        return {"name": name, "config": cfg}
    except Exception:
        raise HTTPException(status_code=500, detail='load_failed')


@router.post("/config/{name}")
async def set_config_route(name: str, body: Any = Body(...), auth: object = Depends(require_scopes('admin'))):
    cfg = _normalize_config_body(body)
    try:
        from src.connectors.registry import set_config
        set_config(name, cfg)
        # Keep runtime integration clients in sync with persisted config so
        # routes that enrich from live singleton clients observe the same
        # state regardless of router ordering (specific vs compat routes).
        try:
            lname = str(name or '').strip().lower()
            if lname == 'tenable':
                try:
                    from integrations.tenable_client import CLIENT as _TENABLE_CLIENT  # type: ignore
                except Exception:
                    try:
                        from src.integrations.tenable_client import CLIENT as _TENABLE_CLIENT  # type: ignore
                    except Exception:
                        _TENABLE_CLIENT = None  # type: ignore
                if _TENABLE_CLIENT is not None:
                    await _TENABLE_CLIENT.config(cfg)
            elif lname == 'qualys':
                try:
                    from integrations.qualys_client import CLIENT as _QUALYS_CLIENT  # type: ignore
                except Exception:
                    try:
                        from src.integrations.qualys_client import CLIENT as _QUALYS_CLIENT  # type: ignore
                    except Exception:
                        _QUALYS_CLIENT = None  # type: ignore
                if _QUALYS_CLIENT is not None:
                    await _QUALYS_CLIENT.config(cfg)
        except Exception:
            pass
        return {"saved": True, "name": name}
    except Exception:
        raise HTTPException(status_code=500, detail='save_failed')


# Backwards-compatible integrations path (non-admin prefix) used by older UI
compat_router = APIRouter(prefix="/api/v1/integrations", tags=["integrations-compat"]) 


@compat_router.get('/{name}/config')
async def compat_get_config(name: str, auth: object = Depends(require_scopes('admin'))):
    return await get_config_route(name, auth=auth)


@compat_router.post('/{name}/config')
async def compat_set_config(name: str, body: Any = Body(...), auth: object = Depends(require_scopes('admin'))):
    return await set_config_route(name, body, auth=auth)


@compat_router.get('/{name}/secrets')
async def compat_get_secrets(name: str, auth: object = Depends(require_scopes('admin'))):
    return await get_secrets(name, auth=auth)


@compat_router.post('/{name}/secrets')
async def compat_set_secrets(name: str, body: SecretsBody, auth: object = Depends(require_scopes('admin'))):
    # reuse set_secrets implementation
    # FastAPI will validate body
    return await set_secrets(name, body, request=None, auth=auth)

