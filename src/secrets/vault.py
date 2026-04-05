"""Secret Vault Integration Layer

Provides simple pluggable secret storage that works for both cloud-native and
on-prem deployments. Available backends (env var VAULT_BACKEND):
 - env (default): read-only env lookups.
 - file: JSON file persisted under VAULT_FILE_PATH (demo/dev only).
 - hashicorp: HashiCorp Vault KV v2 via hvac (recommended for prod/on-prem).
 - azure/aws: placeholders until cloud SDK wiring is completed.

Functions raise minimal exceptions & fall back to env reads when necessary.
"""
from __future__ import annotations
import os, json
from typing import Optional
import logging

logger = logging.getLogger(__name__)

_HVAC_CLIENT = None

def _backend() -> str:
    return os.getenv('VAULT_BACKEND','env').lower()

def _file_path() -> str:
    return os.getenv('VAULT_FILE_PATH','data/secrets_store.json')

def _ensure_file():
    if _backend() == 'file':
        try:
            path = _file_path()
            os.makedirs(os.path.dirname(path), exist_ok=True)
            if not os.path.exists(path):
                with open(path,'w',encoding='utf-8') as f:
                    json.dump({}, f)
        except Exception as e:
            logger.warning(f"Vault file init failed: {e}")

def _load_file() -> dict:
    _ensure_file()
    try:
        with open(_file_path(),'r',encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}

def _save_file(data: dict) -> None:
    try:
        with open(_file_path(),'w',encoding='utf-8') as f:
            json.dump(data, f)
    except Exception as e:
        logger.warning(f"Vault file save failed: {e}")

def _hashicorp_mount_and_path(name: str) -> tuple[str, str]:
    mount = os.getenv('VAULT_KV_MOUNT','secret').strip('/')
    normalized = name.strip().lstrip('/').replace('\\','/')
    return mount or 'secret', normalized

def _hvac_client():
    global _HVAC_CLIENT
    if _HVAC_CLIENT is not None:
        return _HVAC_CLIENT
    addr = os.getenv('VAULT_ADDR')
    token = os.getenv('VAULT_TOKEN')
    if not (addr and token):
        logger.warning('HashiCorp backend selected without VAULT_ADDR/VAULT_TOKEN')
        return None
    verify_env = os.getenv('VAULT_VERIFY','1').lower()
    verify = verify_env not in {'0','false','no'}
    try:
        import hvac  # type: ignore
    except Exception as exc:  # pragma: no cover - optional dependency
        logger.warning('hvac module missing for HashiCorp backend: %s', exc)
        return None
    try:
        client = hvac.Client(url=addr, token=token, verify=verify)
        if not client.is_authenticated():
            logger.warning('HashiCorp Vault authentication failed')
            return None
        _HVAC_CLIENT = client
        return client
    except Exception as exc:  # pragma: no cover - hvac runtime failures
        logger.warning('HashiCorp Vault client init failed: %s', exc)
        return None

def _hashicorp_get(name: str) -> Optional[str]:
    client = _hvac_client()
    if client is None:
        return None
    mount, path = _hashicorp_mount_and_path(name)
    try:
        resp = client.secrets.kv.v2.read_secret_version(path=path, mount_point=mount)
        data = resp.get('data', {}).get('data', {}) if isinstance(resp, dict) else {}
        if not data:
            return None
        return data.get('value') or next(iter(data.values()), None)
    except Exception as exc:  # pragma: no cover - hvac runtime
        logger.warning('HashiCorp Vault read failed for %s: %s', name, exc)
        return None

def _hashicorp_set(name: str, value: str) -> bool:
    client = _hvac_client()
    if client is None:
        return False
    mount, path = _hashicorp_mount_and_path(name)
    try:
        client.secrets.kv.v2.create_or_update_secret(path=path, mount_point=mount, secret={'value': value})
        return True
    except Exception as exc:  # pragma: no cover - hvac runtime
        logger.warning('HashiCorp Vault write failed for %s: %s', name, exc)
        return False

def get_secret(name: str) -> Optional[str]:
    backend = _backend()
    if backend == 'env':
        return os.getenv(name)
    if backend == 'file':
        data = _load_file(); return data.get(name)
    if backend in {'hashicorp','vault','hvac'}:
        secret = _hashicorp_get(name)
        return secret if secret is not None else os.getenv(name)
    if backend == 'azure':  # placeholder
        logger.debug('Azure vault backend not implemented; fallback env')
        return os.getenv(name)
    if backend == 'aws':
        logger.debug('AWS vault backend not implemented; fallback env')
        return os.getenv(name)
    return None

def set_secret(name: str, value: str) -> bool:
    backend = _backend()
    if backend == 'env':  # cannot persist securely; reject
        return False
    if backend == 'file':
        data = _load_file(); data[name] = value; _save_file(data); return True
    if backend in {'hashicorp','vault','hvac'}:
        return _hashicorp_set(name, value)
    # Future azure/aws implementations here
    return False

__all__ = ['get_secret','set_secret']
