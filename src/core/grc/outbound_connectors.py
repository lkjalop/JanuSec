"""Explicitly approved outbound connectors for GRC systems of record."""

from __future__ import annotations
from src.security.http_transport import safe_urlopen

import json
import os
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from src.core.evidence_contract.records import canonical_hash


SUPPORTED_TARGETS = {"servicenow", "vanta", "logicgate", "protecht", "ideagen"}


@dataclass(frozen=True, slots=True)
class GRCConnectorConfig:
    target: str
    endpoint: str
    token: str
    timeout_seconds: float = 20.0


def config_from_environment(target: str) -> GRCConnectorConfig:
    normalized = target.lower().strip()
    if normalized not in SUPPORTED_TARGETS:
        raise ValueError("unsupported_grc_export_target")
    prefix = f"JANUSEC_GRC_{normalized.upper()}"
    endpoint, token = os.getenv(f"{prefix}_URL", "").strip(), os.getenv(f"{prefix}_TOKEN", "").strip()
    if not endpoint or not token:
        raise RuntimeError(f"{normalized}_connector_not_configured")
    if not endpoint.startswith("https://"):
        raise RuntimeError("grc_connector_requires_https")
    return GRCConnectorConfig(target=normalized, endpoint=endpoint, token=token)


def _http_sender(config: GRCConnectorConfig, body: bytes, headers: dict[str, str]) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(config.endpoint, data=body, headers=headers, method="POST")
    with safe_urlopen(request, timeout=config.timeout_seconds) as response:  # noqa: S310 - endpoint is explicit admin config
        raw = response.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            payload = {"response_text": raw[:2000]}
        return int(response.status), payload


def dispatch_approved_finding(
    *, export_payload: Mapping[str, Any], config: GRCConnectorConfig,
    approved_by: str, approval_receipt_hash: str, explicit_approval: bool,
    sender: Callable[[GRCConnectorConfig, bytes, dict[str, str]], tuple[int, dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    if not explicit_approval or not approved_by or not approval_receipt_hash:
        raise PermissionError("explicit_approved_grc_dispatch_required")
    if config.target != str(export_payload.get("target") or ""):
        raise ValueError("grc_connector_target_mismatch")
    idempotency_key = str(export_payload.get("idempotency_key") or "")
    if not idempotency_key:
        raise ValueError("grc_export_idempotency_key_required")
    body = json.dumps(dict(export_payload), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {config.token}", "Content-Type": "application/json",
        "Idempotency-Key": idempotency_key, "User-Agent": "JanusSec-GRC-Bridge/1",
    }
    status_code, response = (sender or _http_sender)(config, body, headers)
    external_id = response.get("sys_id") or response.get("id")
    if not external_id and isinstance(response.get("result"), Mapping):
        external_id = response["result"].get("sys_id") or response["result"].get("id")
    content = {
        "schema_version": "janusec.grc-dispatch-receipt/v1", "target": config.target,
        "endpoint_hash": canonical_hash({"endpoint": config.endpoint}),
        "idempotency_key": idempotency_key, "approved_by": approved_by,
        "approval_receipt_hash": approval_receipt_hash,
        "request_hash": canonical_hash(dict(export_payload)), "http_status": status_code,
        "status": "dispatched" if 200 <= status_code < 300 else "failed",
        "external_id": external_id, "response_hash": canonical_hash(response),
    }
    return {**content, "content_hash": canonical_hash(content)}


__all__ = [
    "GRCConnectorConfig", "SUPPORTED_TARGETS", "config_from_environment",
    "dispatch_approved_finding",
]
