from __future__ import annotations

import base64
import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional
import logging

try:  # pragma: no cover - optional dependency
    from cryptography.fernet import Fernet  # type: ignore
except Exception:  # pragma: no cover
    Fernet = None  # type: ignore

from src.core.secrets import SecretLoader
try:  # pragma: no cover
    from src.security.hsm_attestor import HardwareAttestorClient  # type: ignore
except Exception:  # pragma: no cover
    HardwareAttestorClient = None  # type: ignore

LOGGER = logging.getLogger(__name__)


@dataclass
class EncryptionEnvelope:
    key_id: str
    version: int
    mode: str
    issued_at: float
    sealed: bool
    scope: str | None
    attestation: Optional[Dict[str, Any]] = None
    _fernet: Any = None
    _xor_key: Optional[bytes] = None

    @classmethod
    def from_secret(
        cls,
        *,
        key_bytes: bytes,
        key_id: str,
        version: int,
        scope: str | None,
        sealed: bool,
        issued_at: Optional[float] = None,
        attestation: Optional[Dict[str, Any]] = None,
    ) -> "EncryptionEnvelope":
        fernet_inst = None
        xor_key = None
        if Fernet is not None:
            try:
                fernet_inst = Fernet(key_bytes)
            except Exception:
                fernet_inst = None
        if fernet_inst is None:
            xor_key = key_bytes
        mode = "fernet" if fernet_inst else "xor"
        return cls(
            key_id=key_id,
            version=version,
            mode=mode,
            issued_at=issued_at or time.time(),
            sealed=sealed,
            scope=scope,
            attestation=attestation,
            _fernet=fernet_inst,
            _xor_key=xor_key,
        )

    def encrypt(self, data: bytes) -> bytes:
        if self._fernet:
            return self._fernet.encrypt(data)
        if self._xor_key:
            return bytes(b ^ self._xor_key[i % len(self._xor_key)] for i, b in enumerate(data))
        return data

    def decrypt(self, data: bytes) -> bytes:
        if self._fernet:
            return self._fernet.decrypt(data)
        if self._xor_key:
            return bytes(b ^ self._xor_key[i % len(self._xor_key)] for i, b in enumerate(data))
        return data

    def describe(self) -> Dict[str, Any]:
        return {
            "key_id": self.key_id,
            "version": self.version,
            "mode": self.mode,
            "issued_at": self.issued_at,
            "sealed": self.sealed,
            "scope": self.scope,
            "attestation": self.attestation,
        }


class MemoryKeyManager:
    """Coordinate per-tenant encryption material with optional rotation + audit logging."""

    def __init__(
        self,
        *,
        manifest_path: str | Path = "data/memory_jobs/key_manifest.json",
        audit_path: str | Path = "data/memory_jobs/key_audit.log",
        rotation_seconds: Optional[int] = None,
        loader: Optional[SecretLoader] = None,
    ) -> None:
        self.manifest_path = Path(manifest_path)
        self.audit_path = Path(audit_path)
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        self.rotation_seconds = (
            rotation_seconds
            if rotation_seconds is not None
            else int(os.getenv("MEMORY_KEY_ROTATION_SECONDS", str(7 * 24 * 3600)))
        )
        self.loader = loader or SecretLoader()
        self.default_secret = os.getenv("MEMORY_KMS_SECRET_NAME", "MEMORY_ENCRYPTION_KEY")
        self.hardware_mode = os.getenv("MEMORY_HARDWARE_SEALING", "0").lower() in {"1", "true", "yes"}
        self._lock = threading.RLock()
        self._manifest: Dict[str, Dict[str, Any]] = self._load_manifest()
        if HardwareAttestorClient and os.getenv("MEMORY_HSM_DISABLE", "0").lower() not in {"1", "true", "yes"}:
            try:
                self.attestor = HardwareAttestorClient()
            except Exception as exc:  # pragma: no cover
                LOGGER.warning("memory_attestor_init_failed error=%s", exc)
                self.attestor = None
        else:
            self.attestor = None

    # ------------------------------------------------------------------
    def issue_envelope(self, tenant_id: Optional[str]) -> EncryptionEnvelope:
        scope = (tenant_id or "").lower() or "default"
        now = time.time()
        with self._lock:
            record = self._manifest.get(scope)
            if not record or (self.rotation_seconds and now - record.get("issued_at", 0) > self.rotation_seconds):
                record = self._rotate_locked(scope, record)
            secret_name = record.get("secret_name") or self.default_secret
            version = int(record.get("version") or 1)
            if self.attestor:
                try:
                    record["attestation"] = self.attestor.attest(scope, version=version)
                    self._persist_manifest()
                except Exception as exc:  # pragma: no cover
                    LOGGER.warning("memory_attestor_failed scope=%s error=%s", scope, exc)
            key_bytes = self._load_secret(secret_name, scope)
            envelope = EncryptionEnvelope.from_secret(
                key_bytes=key_bytes,
                key_id=f"{secret_name}:{scope}",
                version=version,
                scope=scope,
                sealed=self.hardware_mode,
                attestation=record.get("attestation"),
            )
            return envelope

    def resume_envelope(self, descriptor: Dict[str, Any]) -> Optional[EncryptionEnvelope]:
        scope = descriptor.get("scope")
        key_id = descriptor.get("key_id")
        if not key_id:
            return None
        secret_name = key_id.split(":")[0]
        version = int(descriptor.get("version") or 1)
        issued_at = float(descriptor.get("issued_at") or time.time())
        key_bytes = self._load_secret(secret_name, scope or "default")
        return EncryptionEnvelope.from_secret(
            key_bytes=key_bytes,
            key_id=key_id,
            version=version,
            scope=scope,
            sealed=self.hardware_mode,
            issued_at=issued_at,
            attestation=descriptor.get("attestation"),
        )

    def describe_scope(self, scope: Optional[str]) -> Optional[Dict[str, Any]]:
        scope_id = (scope or "").lower() or "default"
        record = self._manifest.get(scope_id)
        return dict(record) if record else None

    def describe_scope(self, scope: Optional[str]) -> Optional[Dict[str, Any]]:
        scope_id = (scope or "").lower() or "default"
        return self._manifest.get(scope_id)

    # ------------------------------------------------------------------ helpers
    def _load_manifest(self) -> Dict[str, Dict[str, Any]]:
        if not self.manifest_path.exists():
            return {}
        try:
            data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except Exception:
            return {}
        if not isinstance(data, dict):
            return {}
        manifests = data.get("tenants")
        return manifests if isinstance(manifests, dict) else {}

    def _persist_manifest(self) -> None:
        payload = {"tenants": self._manifest}
        try:
            self.manifest_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _rotate_locked(self, scope: str, record: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        version = (int(record.get("version") or 0) + 1) if record else 1
        secret_name = record.get("secret_name") if record else self.default_secret
        new_record = {"version": version, "secret_name": secret_name, "issued_at": time.time()}
        self._manifest[scope] = new_record
        self._persist_manifest()
        self._audit_event("rotate", scope, version)
        return new_record

    def _load_secret(self, name: str, scope: str) -> bytes:
        raw = self.loader.get(name, scope=scope) or self.loader.get(name)
        if not raw:
            raise RuntimeError(f"memory_kms_secret_missing:{name}")
        try:
            return base64.urlsafe_b64decode(raw.encode("utf-8"))
        except Exception:
            return raw.encode("utf-8")

    def _audit_event(self, action: str, scope: str, version: int) -> None:
        entry = {
            "ts": time.time(),
            "action": action,
            "scope": scope,
            "version": version,
            "hardware_sealed": self.hardware_mode,
        }
        try:
            with self.audit_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry) + "\n")
        except Exception:
            pass


__all__ = ["MemoryKeyManager", "EncryptionEnvelope"]
