"""Secret manager abstraction for per-tenant OAuth tokens.

Defaults to an encrypted file-based store but can be swapped to Vault or Azure
Key Vault via the `SECRET_BACKEND` (or `SECRET_MANAGER_BACKEND`) environment
variable. Supported values: `tenant` (default), `vault`, `azure`, `memory`.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import time
from typing import Dict, Optional

import requests
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

STORE_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "tenant_store")
os.makedirs(STORE_DIR, exist_ok=True)


class SecretBackendError(RuntimeError):
    """Raised when a secret backend cannot fulfill a request."""


class BaseSecretBackend:
    def save(self, key: str, payload: Dict) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def load(self, key: str) -> Optional[Dict]:  # pragma: no cover - interface
        raise NotImplementedError

    def delete(self, key: str) -> None:  # pragma: no cover - interface
        raise NotImplementedError


def _key_path() -> str:
    return os.path.join(STORE_DIR, "fernet.key")


def _ensure_key() -> bytes:
    kp = _key_path()
    if os.path.exists(kp):
        return open(kp, "rb").read()
    k = Fernet.generate_key()
    open(kp, "wb").write(k)
    return k


class FileSecretBackend(BaseSecretBackend):
    """Original encrypted file-based backend."""

    def __init__(self):
        key = _ensure_key()
        self.fernet = Fernet(key)

    def _path_for(self, key: str) -> str:
        safe = key.replace("/", "_")
        return os.path.join(STORE_DIR, f"{safe}.json.enc")

    def save(self, key: str, payload: Dict) -> None:
        path = self._path_for(key)
        plaintext = json.dumps(payload).encode("utf-8")
        ciphertext = self.fernet.encrypt(plaintext)
        with open(path, "wb") as fh:
            fh.write(ciphertext)

    def load(self, key: str) -> Optional[Dict]:
        path = self._path_for(key)
        if not os.path.exists(path):
            return None
        try:
            ciphertext = open(path, "rb").read()
        except FileNotFoundError:
            return None
        plaintext = self.fernet.decrypt(ciphertext)
        return json.loads(plaintext.decode("utf-8"))

    def delete(self, key: str) -> None:
        path = self._path_for(key)
        try:
            os.remove(path)
        except FileNotFoundError:
            pass


class MemorySecretBackend(BaseSecretBackend):
    """Lightweight backend useful for tests."""

    _store: Dict[str, Dict] = {}

    def save(self, key: str, payload: Dict) -> None:
        MemorySecretBackend._store[key] = payload.copy()

    def load(self, key: str) -> Optional[Dict]:
        value = MemorySecretBackend._store.get(key)
        return value.copy() if value is not None else None

    def delete(self, key: str) -> None:
        MemorySecretBackend._store.pop(key, None)


class VaultSecretBackend(BaseSecretBackend):
    def __init__(self):
        self.addr = os.getenv("VAULT_ADDR")
        self.token = os.getenv("VAULT_TOKEN")
        self.mount = os.getenv("VAULT_KV_MOUNT", "secret")
        if not self.addr or not self.token:
            raise SecretBackendError("VAULT_ADDR and VAULT_TOKEN must be set for Vault backend")

    def _url(self, path: str) -> str:
        return f"{self.addr.rstrip('/')}/v1/{path.lstrip('/')}"

    def _headers(self) -> Dict[str, str]:
        return {"X-Vault-Token": self.token}

    def save(self, key: str, payload: Dict) -> None:
        path = f"{self.mount}/data/{key}"
        resp = requests.post(self._url(path), headers=self._headers(), json={"data": payload}, timeout=10)
        if resp.status_code >= 400:
            raise SecretBackendError(f"Vault save failed ({resp.status_code}): {resp.text}")

    def load(self, key: str) -> Optional[Dict]:
        path = f"{self.mount}/data/{key}"
        resp = requests.get(self._url(path), headers=self._headers(), timeout=10)
        if resp.status_code == 404:
            return None
        if resp.status_code >= 400:
            raise SecretBackendError(f"Vault load failed ({resp.status_code}): {resp.text}")
        data = resp.json()
        return data.get("data", {}).get("data")

    def delete(self, key: str) -> None:
        path = f"{self.mount}/metadata/{key}"
        resp = requests.delete(self._url(path), headers=self._headers(), timeout=10)
        if resp.status_code not in (200, 204, 404):
            raise SecretBackendError(f"Vault delete failed ({resp.status_code}): {resp.text}")


def _sanitize_secret_name(name: str) -> str:
    return name.replace("/", "-").replace(":", "-")


class AzureKeyVaultSecretBackend(BaseSecretBackend):
    def __init__(self):
        self.vault_url = os.getenv("AZURE_KEY_VAULT_URL")
        self.token = os.getenv("AZURE_KEY_VAULT_TOKEN")
        self.api_version = os.getenv("AZURE_KEY_VAULT_API_VERSION", "7.3")
        if not self.vault_url or not self.token:
            raise SecretBackendError("AZURE_KEY_VAULT_URL and AZURE_KEY_VAULT_TOKEN must be set for Azure backend")

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

    def save(self, key: str, payload: Dict) -> None:
        name = _sanitize_secret_name(key)
        url = f"{self.vault_url.rstrip('/')}/secrets/{name}?api-version={self.api_version}"
        encoded = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")
        resp = requests.put(url, headers=self._headers(), json={"value": encoded, "contentType": "application/json"}, timeout=10)
        if resp.status_code >= 400:
            raise SecretBackendError(f"Azure Key Vault save failed ({resp.status_code}): {resp.text}")

    def load(self, key: str) -> Optional[Dict]:
        name = _sanitize_secret_name(key)
        url = f"{self.vault_url.rstrip('/')}/secrets/{name}?api-version={self.api_version}"
        resp = requests.get(url, headers=self._headers(), timeout=10)
        if resp.status_code == 404:
            return None
        if resp.status_code >= 400:
            raise SecretBackendError(f"Azure Key Vault load failed ({resp.status_code}): {resp.text}")
        encoded = resp.json().get("value")
        if not encoded:
            return None
        decoded = base64.b64decode(encoded.encode("utf-8"))
        return json.loads(decoded.decode("utf-8"))

    def delete(self, key: str) -> None:
        name = _sanitize_secret_name(key)
        url = f"{self.vault_url.rstrip('/')}/secrets/{name}?api-version={self.api_version}"
        resp = requests.delete(url, headers=self._headers(), timeout=10)
        if resp.status_code not in (200, 204, 404):
            raise SecretBackendError(f"Azure Key Vault delete failed ({resp.status_code}): {resp.text}")


def _build_backend(backend_name: Optional[str]) -> BaseSecretBackend:
    target = (backend_name or os.getenv("SECRET_BACKEND") or os.getenv("SECRET_MANAGER_BACKEND") or "tenant").lower()
    if target in ("vault", "hashicorp"):
        try:
            logger.info("Using Vault secret backend")
            return VaultSecretBackend()
        except SecretBackendError as exc:
            logger.warning("Vault backend unavailable (%s); falling back to file store", exc)
    elif target in ("azure", "azurekeyvault", "keyvault"):
        try:
            logger.info("Using Azure Key Vault secret backend")
            return AzureKeyVaultSecretBackend()
        except SecretBackendError as exc:
            logger.warning("Azure Key Vault backend unavailable (%s); falling back to file store", exc)
    elif target == "memory":
        logger.info("Using in-memory secret backend")
        return MemorySecretBackend()
    logger.info("Using encrypted file secret backend")
    return FileSecretBackend()


class TenantStore:
    """Abstraction used by OAuth routes and workers to persist tenant secrets."""

    def __init__(self, backend: Optional[str] = None):
        self.backend = _build_backend(backend)

    def _token_key(self, tenant_id: str) -> str:
        return f"tenants/{tenant_id}/tokens"

    def save_tokens(self, tenant_id: str, token_payload: Dict) -> None:
        self.backend.save(self._token_key(tenant_id), token_payload)
        # Audit rotation/save event (append-only JSONL for simple audit)
        try:
            audit_dir = os.path.join(STORE_DIR, 'audit')
            os.makedirs(audit_dir, exist_ok=True)
            audit_path = os.path.join(audit_dir, f"{tenant_id}.log")
            entry = {
                'ts': int(time.time()),
                'tenant': tenant_id,
                'action': 'save_tokens',
                'backend': type(self.backend).__name__,
                'summary': {
                    'has_refresh': bool(token_payload.get('refresh_token')),
                    'expires_at': token_payload.get('expires_at')
                }
            }
            with open(audit_path, 'a', encoding='utf-8') as fh:
                fh.write(json.dumps(entry) + "\n")
        except Exception:
            logger.debug('Failed to write tenant audit entry', exc_info=True)

    # Cursor helpers for connectors (SQLite K/V persistent store)
    def _kv_db_path(self) -> str:
        dbdir = os.path.join(STORE_DIR, 'kv')
        os.makedirs(dbdir, exist_ok=True)
        return os.path.join(dbdir, 'tenants_kv.db')

    def _ensure_kv_db(self):
        path = self._kv_db_path()
        import sqlite3
        conn = sqlite3.connect(path, timeout=5)
        cur = conn.cursor()
        cur.execute('''
            CREATE TABLE IF NOT EXISTS kv(
                tenant TEXT NOT NULL,
                provider TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT,
                updated_at INTEGER,
                PRIMARY KEY(tenant, provider, key)
            )
        ''')
        conn.commit()
        conn.close()

    def save_cursor(self, tenant_id: str, provider: str, cursor_key: str, cursor_value: str):
        try:
            import sqlite3
            self._ensure_kv_db()
            path = self._kv_db_path()
            conn = sqlite3.connect(path, timeout=5)
            cur = conn.cursor()
            cur.execute('REPLACE INTO kv(tenant,provider,key,value,updated_at) VALUES(?,?,?,?,?)', (tenant_id, provider, cursor_key, cursor_value, int(time.time())))
            conn.commit()
            conn.close()
        except Exception:
            logger.exception('Failed to save cursor to kv store')

    def load_cursor(self, tenant_id: str, provider: str, cursor_key: str) -> Optional[str]:
        try:
            import sqlite3
            path = self._kv_db_path()
            if not os.path.exists(path):
                return None
            conn = sqlite3.connect(path, timeout=5)
            cur = conn.cursor()
            cur.execute('SELECT value FROM kv WHERE tenant=? AND provider=? AND key=?', (tenant_id, provider, cursor_key))
            row = cur.fetchone()
            conn.close()
            if row:
                return row[0]
        except Exception:
            logger.exception('Failed to load cursor from kv store')
        return None

    def load_tokens(self, tenant_id: str) -> Optional[Dict]:
        return self.backend.load(self._token_key(tenant_id))

    def delete_tokens(self, tenant_id: str) -> None:
        self.backend.delete(self._token_key(tenant_id))
        try:
            audit_dir = os.path.join(STORE_DIR, 'audit')
            os.makedirs(audit_dir, exist_ok=True)
            audit_path = os.path.join(audit_dir, f"{tenant_id}.log")
            entry = {
                'ts': int(time.time()),
                'tenant': tenant_id,
                'action': 'delete_tokens',
                'backend': type(self.backend).__name__,
            }
            with open(audit_path, 'a', encoding='utf-8') as fh:
                fh.write(json.dumps(entry) + "\n")
        except Exception:
            logger.debug('Failed to write tenant audit entry', exc_info=True)

    def try_refresh_tokens(self, tenant_id: str) -> bool:
        """Attempt to refresh tokens using refresh_token. This is a light helper that will:
        - load existing tokens
        - if a refresh_token is present, call the connector refresh flow (best-effort via saved client creds)
        - persist the new tokens
        Returns True if refreshed and saved, False otherwise.
        """
        toks = self.load_tokens(tenant_id) or {}
        refresh = toks.get('refresh_token')
        if not refresh:
            return False
        client_id = toks.get('client_id')
        client_secret = toks.get('client_secret')
        if not client_id or not client_secret:
            return False
        try:
            # Try MS Graph-style token endpoint by default
            data = {
                'client_id': client_id,
                'client_secret': client_secret,
                'refresh_token': refresh,
                'grant_type': 'refresh_token',
            }
            r = requests.post(os.getenv('OAUTH_TOKEN_URL_OVERRIDE') or 'https://login.microsoftonline.com/common/oauth2/v2.0/token', data=data, timeout=15)
            r.raise_for_status()
            new = r.json()
            # compute absolute expiry if provided
            if new.get('expires_in'):
                new['expires_at'] = int(time.time()) + int(new.get('expires_in'))
            # carry client creds for future refreshes
            new['client_id'] = client_id
            new['client_secret'] = client_secret
            self.save_tokens(tenant_id, new)
            return True
        except Exception:
            return False


if __name__ == "__main__":  # pragma: no cover - helper
    print("TenantStore helper. Use in integration code to persist per-tenant tokens.")
