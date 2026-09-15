from __future__ import annotations

import base64
import json
import os
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional
import logging

from src.utils.webhook_notify import post_webhook

LOGGER = logging.getLogger(__name__)
_LATEST_ATTESTOR: "HardwareAttestorClient | None" = None


class HSMIntegrityError(RuntimeError):
    def __init__(self, backend: str, detail: str) -> None:
        super().__init__(detail)
        self.backend = backend
        self.detail = detail


class _BaseProvider:
    name = "base"

    def attest(self, scope: str, version: int) -> Dict[str, Any]:
        raise NotImplementedError


class _HTTPProvider(_BaseProvider):
    name = "http"

    def __init__(self, endpoint: Optional[str], token: Optional[str]) -> None:
        self.endpoint = endpoint or os.getenv("MEMORY_HSM_ENDPOINT")
        self.token = token or os.getenv("MEMORY_HSM_TOKEN")

    def attest(self, scope: str, version: int) -> Dict[str, Any]:
        if not self.endpoint:
            raise HSMIntegrityError(self.name, "endpoint_not_configured")
        payload = {"scope": scope, "version": version, "ts": time.time()}
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(self.endpoint, data=data, headers=self._headers(), method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:  # nosec B310
            raw = resp.read().decode("utf-8")
            parsed = json.loads(raw or "{}")
            parsed.setdefault("proof", parsed.get("attestation") or parsed.get("token"))
            parsed.setdefault("backend", self.name)
            return parsed

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers


class _AWSProvider(_BaseProvider):
    name = "aws"

    def __init__(self) -> None:
        region = os.getenv("MEMORY_HSM_AWS_REGION") or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")
        key_id = os.getenv("MEMORY_HSM_AWS_KEY_ID")
        try:
            import boto3  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise HSMIntegrityError(self.name, f"boto3_missing:{exc}") from exc
        if not region:
            raise HSMIntegrityError(self.name, "region_not_configured")
        self.client = boto3.client("kms", region_name=region)
        self.key_id = key_id

    def attest(self, scope: str, version: int) -> Dict[str, Any]:
        try:
            if self.key_id:
                resp = self.client.generate_data_key_without_plaintext(KeyId=self.key_id, KeySpec="AES_256")
                cipher = resp.get("CiphertextBlob")
                if not cipher:
                    raise HSMIntegrityError(self.name, "ciphertext_missing")
                proof = base64.b64encode(cipher).decode("utf-8")
            else:
                resp = self.client.generate_random(NumberOfBytes=32)
                rnd = resp.get("Plaintext") or resp.get("Random")
                if not rnd:
                    raise HSMIntegrityError(self.name, "rng_output_missing")
                proof = base64.b64encode(rnd if isinstance(rnd, (bytes, bytearray)) else rnd.encode("utf-8")).decode("utf-8")
            return {"proof": proof, "backend": self.name, "key_id": self.key_id}
        except HSMIntegrityError:
            raise
        except Exception as exc:  # pragma: no cover
            raise HSMIntegrityError(self.name, str(exc)) from exc


class _AzureProvider(_BaseProvider):
    name = "azure"

    def __init__(self) -> None:
        self.vault_url = os.getenv("MEMORY_HSM_AZURE_VAULT_URL")
        self.key_name = os.getenv("MEMORY_HSM_AZURE_KEY_NAME")
        if not (self.vault_url and self.key_name):
            raise HSMIntegrityError(self.name, "vault_or_key_not_configured")
        try:
            from azure.identity import DefaultAzureCredential  # type: ignore
            from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm  # type: ignore
            from azure.keyvault.keys import KeyClient  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise HSMIntegrityError(self.name, f"azure_sdk_missing:{exc}") from exc
        credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
        key_client = KeyClient(vault_url=self.vault_url, credential=credential)
        key = key_client.get_key(self.key_name)
        self.crypto_client = CryptographyClient(key, credential=credential)
        self.algorithm = SignatureAlgorithm.rs256

    def attest(self, scope: str, version: int) -> Dict[str, Any]:
        try:
            payload = f"{scope}:{version}:{int(time.time())}".encode("utf-8")
            digest = payload[:32] if len(payload) >= 32 else payload.ljust(32, b"\x00")
            signed = self.crypto_client.sign(self.algorithm, digest)
            proof = base64.b64encode(signed.signature).decode("utf-8")
            return {"proof": proof, "backend": self.name, "key": self.key_name}
        except Exception as exc:  # pragma: no cover
            raise HSMIntegrityError(self.name, str(exc)) from exc


class _GCPProvider(_BaseProvider):
    name = "gcp"

    def __init__(self) -> None:
        self.resource = os.getenv("MEMORY_HSM_GCP_RESOURCE")
        if not self.resource:
            raise HSMIntegrityError(self.name, "resource_not_configured")
        try:
            from google.cloud import kms_v1  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise HSMIntegrityError(self.name, f"gcp_sdk_missing:{exc}") from exc
        self.client = kms_v1.KeyManagementServiceClient()

    def attest(self, scope: str, version: int) -> Dict[str, Any]:
        try:
            payload = f"{scope}:{version}:{int(time.time())}".encode("utf-8")
            digest = payload[:32] if len(payload) >= 32 else payload.ljust(32, b"\x00")
            resp = self.client.mac_sign(request={"name": self.resource, "data": digest})
            proof = base64.b64encode(resp.mac).decode("utf-8")
            return {"proof": proof, "backend": self.name, "resource": self.resource}
        except Exception as exc:  # pragma: no cover
            raise HSMIntegrityError(self.name, str(exc)) from exc


class HardwareAttestorClient:
    """Wrapper around multiple HSM/KMS attestor backends with tamper logging."""

    def __init__(
        self,
        *,
        endpoint: Optional[str] = None,
        token: Optional[str] = None,
        log_path: str | Path = "data/memory_jobs/hsm_attestations.log",
        cache_path: str | Path = "data/memory_jobs/hsm_cache.json",
        alert_path: str | Path = "data/memory_jobs/hsm_alerts.log",
        health_interval: Optional[int] = None,
        alert_webhook: Optional[str] = None,
    ) -> None:
        self.log_path = Path(log_path)
        self.cache_path = Path(cache_path)
        self.alert_path = Path(alert_path)
        for p in (self.log_path, self.cache_path, self.alert_path):
            p.parent.mkdir(parents=True, exist_ok=True)
        backend = (os.getenv("MEMORY_HSM_BACKEND") or "auto").lower()
        self.provider = self._build_provider(backend, endpoint, token)
        self.alert_webhook = alert_webhook or os.getenv("MEMORY_HSM_ALERT_WEBHOOK")
        self._customer_webhooks = self._parse_webhooks(os.getenv("MEMORY_HSM_CUSTOMER_WEBHOOKS"))
        self._health_lock = threading.RLock()
        self._health_snapshot: Dict[str, Any] = {
            "backend": getattr(self.provider, "name", "local"),
            "last_status": "idle",
            "last_poll_ts": None,
            "last_ok_ts": None,
            "last_error": None,
            "last_tamper_detail": None,
            "poll_interval": None,
            "alert_count": 0,
            "customer_webhook_count": len(self._customer_webhooks),
        }
        interval = (
            health_interval
            if health_interval is not None
            else int(os.getenv("MEMORY_HSM_HEALTH_INTERVAL_SECONDS", "0") or 0)
        )
        self._health_thread: Optional[threading.Thread] = None
        if interval > 0 and not isinstance(self.provider, _LocalFallbackProvider):
            self._health_thread = threading.Thread(
                target=self._health_loop, args=(interval,), name="hsm-health", daemon=True
            )
            self._health_thread.start()
        self._update_health_snapshot(poll_interval=interval or None)
        global _LATEST_ATTESTOR
        _LATEST_ATTESTOR = self

    def _build_provider(self, backend: str, endpoint: Optional[str], token: Optional[str]) -> _BaseProvider:
        try:
            if backend == "aws":
                return _AWSProvider()
            if backend == "azure":
                return _AzureProvider()
            if backend == "gcp":
                return _GCPProvider()
            if backend == "http":
                return _HTTPProvider(endpoint, token)
            # auto-detect: prefer explicit endpoint else local token
            if endpoint:
                return _HTTPProvider(endpoint, token)
        except HSMIntegrityError as exc:
            LOGGER.warning("hsm_provider_init_failed backend=%s detail=%s", backend, exc.detail)
        return _LocalFallbackProvider(self.cache_path)

    @staticmethod
    def _parse_webhooks(raw: Optional[str]) -> list[str]:
        if not raw:
            return []
        return [hook.strip() for hook in raw.split(",") if hook.strip()]

    def health_snapshot(self) -> Dict[str, Any]:
        with self._health_lock:
            snapshot = dict(self._health_snapshot)
        snapshot["backend"] = getattr(self.provider, "name", snapshot.get("backend", "local"))
        snapshot["enabled"] = self.enabled()
        snapshot["customer_webhook_count"] = len(self._customer_webhooks)
        return snapshot

    def run_health_check(self) -> Dict[str, Any]:
        now = time.time()
        self._update_health_snapshot(last_poll_ts=now)
        try:
            proof = self.provider.attest("health", 0)
            preview = proof.get("proof") if isinstance(proof, dict) else None
            if isinstance(preview, str) and len(preview) > 48:
                preview = preview[:48] + "..."
            self._update_health_snapshot(last_status="ok", last_ok_ts=now, last_error=None, last_proof=preview)
            return {"status": "ok", "proof": proof}
        except HSMIntegrityError as exc:
            self._update_health_snapshot(
                last_status="error",
                last_error={"backend": exc.backend, "detail": exc.detail, "ts": now},
            )
            self._record_tamper_alert("health", 0, exc, include_customer=True)
            return {"status": "error", "backend": exc.backend, "detail": exc.detail}
        except Exception as exc:  # pragma: no cover
            self._update_health_snapshot(last_status="error", last_error={"detail": str(exc), "ts": now})
            return {"status": "error", "detail": str(exc)}
    def simulate_tamper(self, detail: str = "simulated_tamper") -> Dict[str, Any]:
        """Force a tamper alert for proof/testing so telemetry surfaces red states."""
        backend = getattr(self.provider, "name", "local")
        exc = HSMIntegrityError(backend, detail)
        self._record_tamper_alert("simulate", -1, exc)
        return self.health_snapshot()

    def enabled(self) -> bool:
        return not isinstance(self.provider, _LocalFallbackProvider)

    # ------------------------------------------------------------------
    def attest(self, scope: str, *, version: int) -> Dict[str, Any]:
        payload = {"scope": scope, "version": version, "ts": time.time()}
        try:
            proof = self.provider.attest(scope, version)
        except HSMIntegrityError as exc:
            self._record_tamper_alert(scope, version, exc)
            proof = _issue_local_token(scope, version, self.cache_path)
        record = {
            "scope": scope,
            "version": version,
            "ts": payload["ts"],
            "proof": proof.get("proof") if isinstance(proof, dict) else proof,
            "meta": proof,
        }
        self._append_log(record)
        return record

    def _record_tamper_alert(
        self, scope: str, version: int, exc: HSMIntegrityError, include_customer: bool = True
    ) -> None:
        record = {
            "ts": time.time(),
            "scope": scope,
            "version": version,
            "backend": exc.backend,
            "detail": exc.detail,
        }
        try:
            with self.alert_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record) + "\n")
        except Exception:
            pass
        with self._health_lock:
            self._health_snapshot["last_tamper_detail"] = record
            self._health_snapshot["last_tamper_ts"] = record["ts"]
            self._health_snapshot["last_status"] = "error"
            self._health_snapshot["alert_count"] = int(self._health_snapshot.get("alert_count") or 0) + 1
        payload = {"type": "hsm_tamper", "scope": scope, "version": version, "backend": exc.backend, "detail": exc.detail}
        self._notify_webhooks(payload, include_customer=include_customer)

    def _append_log(self, record: Dict[str, Any]) -> None:
        try:
            with self.log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record) + "\n")
        except Exception:
            pass

    def _health_loop(self, interval: int) -> None:
        while True:
            try:
                time.sleep(interval)
                self.run_health_check()
            except HSMIntegrityError:
                continue
            except Exception:
                continue

    def _notify_webhooks(self, payload: Dict[str, Any], *, include_customer: bool) -> None:
        targets = []
        if self.alert_webhook:
            targets.append(self.alert_webhook)
        if include_customer:
            targets.extend(self._customer_webhooks)
        seen = set()
        for hook in targets:
            if not hook or hook in seen:
                continue
            seen.add(hook)
            post_webhook(hook, payload)

    def _update_health_snapshot(self, **updates: Any) -> None:
        with self._health_lock:
            self._health_snapshot.update(updates)


class _LocalFallbackProvider(_BaseProvider):
    name = "local"

    def __init__(self, cache_path: Path) -> None:
        self.cache_path = cache_path

    def attest(self, scope: str, version: int) -> Dict[str, Any]:
        return _issue_local_token(scope, version, self.cache_path)


def _issue_local_token(scope: str, version: int, cache_path: Path) -> Dict[str, Any]:
    token = f"mock-hsm::{scope}::{version}::{int(time.time())}"
    record = {"proof": token, "backend": "local"}
    try:
        cache = {}
        if cache_path.exists():
            cache = json.loads(cache_path.read_text(encoding="utf-8") or "{}")
        cache[scope] = {"token": token, "version": version, "ts": time.time()}
        cache_path.write_text(json.dumps(cache, indent=2), encoding="utf-8")
    except Exception:
        pass
    return record


def get_latest_attestor() -> Optional[HardwareAttestorClient]:
    return _LATEST_ATTESTOR


__all__ = ["HardwareAttestorClient", "HSMIntegrityError", "get_latest_attestor"]
