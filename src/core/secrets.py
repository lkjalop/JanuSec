from __future__ import annotations

import os
from typing import Any, Dict, Optional


class SecretBackend:
    def get(self, name: str, scope: str | None = None) -> Optional[str]:
        raise NotImplementedError


class EnvSecretBackend(SecretBackend):
    def get(self, name: str, scope: str | None = None) -> Optional[str]:
        if scope:
            v = os.getenv(f'{name}_{scope}'.upper())
            if v:
                return v
        return os.getenv(name.upper())


class VaultSecretBackend(SecretBackend):
    def __init__(self, addr: str | None = None, token: str | None = None) -> None:
        self.addr = addr or os.getenv('VAULT_ADDR')
        self.token = token or os.getenv('VAULT_TOKEN')

    def get(self, name: str, scope: str | None = None) -> Optional[str]:
        # Attempt real HVac client if present; else fallback to env
        if not (self.addr and self.token):
            return EnvSecretBackend().get(name, scope)
        try:
            import hvac  # type: ignore
            client = hvac.Client(url=self.addr, token=self.token)
            kv_path = os.getenv('VAULT_KV_PATH', 'secret/data')
            secret_name = name.lower() if name else ''
            if scope:
                secret_name = f"{secret_name}-{scope.lower()}"
            path = f"{kv_path.rstrip('/')}/{secret_name}"
            res = client.secrets.kv.v2.read_secret_version(path=path)
            data = res.get('data', {}).get('data', {})
            if not data:
                return None
            # convention: value stored under 'value' or name
            return data.get('value') or data.get(name) or next(iter(data.values()))
        except Exception:
            return EnvSecretBackend().get(name, scope)


class AWSKMSBackend(SecretBackend):
    def __init__(self) -> None:
        # In a full impl, set up boto3 client; here we fall back to env
        pass

    def get(self, name: str, scope: str | None = None) -> Optional[str]:
        # Prefer AWS Secrets Manager via boto3 if available
        try:
            import boto3  # type: ignore
            client = boto3.client('secretsmanager', region_name=os.getenv('AWS_REGION') or os.getenv('AWS_DEFAULT_REGION'))
            secret_id = name
            if scope:
                secret_id = f"{name}:{scope}"
            resp = client.get_secret_value(SecretId=secret_id)
            val = resp.get('SecretString')
            return val
        except Exception:
            return EnvSecretBackend().get(name, scope)


class GCPKMSBackend(SecretBackend):
    def __init__(self) -> None:
        # In a full impl, set up google-cloud-kms client; here we fall back to env
        pass

    def get(self, name: str, scope: str | None = None) -> Optional[str]:
        try:
            from google.cloud import secretmanager  # type: ignore
            project = os.getenv('GCP_PROJECT')
            if not project:
                return EnvSecretBackend().get(name, scope)
            client = secretmanager.SecretManagerServiceClient()
            sid = name
            if scope:
                sid = f"{name}-{scope}"
            resource = f"projects/{project}/secrets/{sid}/versions/latest"
            resp = client.access_secret_version(name=resource)
            return resp.payload.data.decode('utf-8') if getattr(resp, 'payload', None) else None
        except Exception:
            return EnvSecretBackend().get(name, scope)


class MockSecretBackend(SecretBackend):
    def __init__(self, mapping: Dict[str, str]):
        self.mapping = mapping

    def get(self, name: str, scope: str | None = None) -> Optional[str]:
        key = f'{name}:{scope}' if scope else name
        return self.mapping.get(key) or self.mapping.get(name)


class SecretLoader:
    def __init__(self, backend: SecretBackend | None = None) -> None:
        self.backend = backend or self._make_backend()
        self._cache: dict[tuple[str, str | None], tuple[Optional[str], float]] = {}
        try:
            self._ttl = float(os.getenv('SECRETS_CACHE_TTL_SECONDS','300') or 300)
        except Exception:
            self._ttl = 300.0

    def _make_backend(self) -> SecretBackend:
        kind = (os.getenv('SECRETS_BACKEND') or 'env').lower()
        if kind == 'vault':
            return VaultSecretBackend()
        if kind == 'awskms':
            return AWSKMSBackend()
        if kind == 'gcpkms':
            return GCPKMSBackend()
        if kind == 'mock':
            return MockSecretBackend({})
        return EnvSecretBackend()

    def get(self, name: str, scope: str | None = None) -> Optional[str]:
        key = (name, scope)
        now = __import__('time').time()
        cached = self._cache.get(key)
        if cached and (now - cached[1]) < self._ttl:
            return cached[0]
        try:
            val = self.backend.get(name, scope)
        except Exception:
            val = None
        self._cache[key] = (val, now)
        return val

    @staticmethod
    def scrub_log(record: Dict[str, Any]) -> Dict[str, Any]:
        redacted = {}
        for k, v in record.items():
            if any(tok in k.lower() for tok in ('secret','token','password','key','credential')):
                redacted[k] = '***'
            else:
                redacted[k] = v
        return redacted

    @staticmethod
    def zeroize(buf: bytearray) -> None:
        for i in range(len(buf)):
            buf[i] = 0
