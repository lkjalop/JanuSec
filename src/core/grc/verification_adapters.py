"""Read-only provider verification adapters with signed before/after receipts.

Adapters never execute remediation.  They retain provider-native responses,
require stable source identifiers, and verify only explicit exact-state claims.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Any, Mapping

from src.core.evidence_contract.asymmetric_signing import DigestSigner
from src.core.evidence_contract.records import canonical_hash
from src.core.evidence_contract.signed_snapshots import sign_snapshot


@dataclass(frozen=True, slots=True)
class ProviderContract:
    provider: str
    id_paths: tuple[str, ...]
    time_paths: tuple[str, ...]
    result_paths: tuple[str, ...]


PROVIDER_CONTRACTS: dict[str, ProviderContract] = {
    "entra_m365": ProviderContract("entra_m365", ("id", "activity.id"), ("createdDateTime", "activityDateTime"), ("status", "result", "activityResult")),
    "aws": ProviderContract("aws", ("eventID", "id"), ("eventTime", "timestamp"), ("errorCode", "responseElements.status", "result")),
    "gcp": ProviderContract("gcp", ("insertId", "operation.id"), ("timestamp", "receiveTimestamp"), ("protoPayload.status", "operation.done", "result")),
    "alibaba": ProviderContract("alibaba", ("eventId", "requestId"), ("eventTime", "eventTimestamp"), ("errorCode", "eventOutcome", "result")),
    "edr": ProviderContract("edr", ("event_id", "id", "detection_id"), ("timestamp", "event_time"), ("status", "action_status", "result")),
    "firewall": ProviderContract("firewall", ("event_id", "session_id", "log_id"), ("timestamp", "event_time"), ("disposition", "action", "result")),
    "veeam": ProviderContract("veeam", ("job_id", "session_id", "report_id"), ("collected_at", "end_time", "timestamp"), ("result", "status", "state")),
}


def _path(value: Mapping[str, Any], dotted: str) -> Any:
    current: Any = value
    for part in dotted.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return None
        current = current[part]
    return current


def _first(value: Mapping[str, Any], paths: tuple[str, ...]) -> tuple[str | None, Any]:
    for path in paths:
        found = _path(value, path)
        if found not in (None, ""):
            return path, found
    return None, None


def _has_path(value: Mapping[str, Any], dotted: str) -> bool:
    current: Any = value
    for part in dotted.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return False
        current = current[part]
    return True


def _time(value: Any) -> dt.datetime | None:
    if value in (None, ""):
        return None
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def build_verification_payload(
    *, provider: str, action_id: str, before_native: Mapping[str, Any],
    after_native: Mapping[str, Any], expected_after: Mapping[str, Any],
    collector_identity: str, request_receipt: Mapping[str, Any] | None = None,
    clock_uncertainty_seconds: float = 0.0,
) -> dict[str, Any]:
    contract = PROVIDER_CONTRACTS.get(provider)
    if contract is None:
        raise ValueError("unsupported_verification_provider")
    if not action_id or not collector_identity or not before_native or not after_native:
        raise ValueError("complete_read_only_verification_input_required")
    if not expected_after:
        raise ValueError("explicit_expected_after_state_required")
    before_id_path, before_id = _first(before_native, contract.id_paths)
    after_id_path, after_id = _first(after_native, contract.id_paths)
    if before_id is None or after_id is None:
        raise ValueError("provider_native_stable_ids_required")
    before_time_path, before_time_value = _first(before_native, contract.time_paths)
    after_time_path, after_time_value = _first(after_native, contract.time_paths)
    before_time, after_time = _time(before_time_value), _time(after_time_value)
    temporal_status = "unknown"
    if before_time and after_time:
        temporal_status = (
            "valid" if after_time + dt.timedelta(seconds=max(0.0, clock_uncertainty_seconds)) >= before_time
            else "invalid_after_precedes_before"
        )
    checks = []
    for path, expected in sorted(expected_after.items()):
        observed = _path(after_native, str(path))
        checks.append({
            "field_path": str(path), "expected": expected, "observed": observed,
            "present": _has_path(after_native, str(path)),
            "matched": _has_path(after_native, str(path)) and observed == expected
            and (not isinstance(expected, bool) or isinstance(observed, bool)),
        })
    _, provider_result = _first(after_native, contract.result_paths)
    all_matched = bool(checks) and all(item["matched"] for item in checks)
    verification_status = (
        "verified" if all_matched and temporal_status == "valid"
        else "failed" if not all_matched or temporal_status == "invalid_after_precedes_before"
        else "unverified"
    )
    return {
        "schema_version": "janusec.provider-verification/v1",
        "provider": provider, "action_id": action_id,
        "collector_identity": collector_identity, "collection_mode": "read_only",
        "before": {
            "provider_record_id": str(before_id), "id_path": before_id_path,
            "observed_at": before_time_value, "time_path": before_time_path,
            "native_hash": canonical_hash(dict(before_native)), "provider_native": dict(before_native),
        },
        "after": {
            "provider_record_id": str(after_id), "id_path": after_id_path,
            "observed_at": after_time_value, "time_path": after_time_path,
            "native_hash": canonical_hash(dict(after_native)), "provider_native": dict(after_native),
        },
        "expected_after": dict(expected_after), "checks": checks,
        "provider_result": provider_result, "temporal_status": temporal_status,
        "clock_uncertainty_seconds": max(0.0, float(clock_uncertainty_seconds)),
        "verification_status": verification_status,
        "request_receipt": dict(request_receipt or {}),
    }


def sign_provider_verification(
    *, tenant_id: str, payload: Mapping[str, Any], version: str,
    valid_from: str, valid_to: str | None = None, signer: DigestSigner | None = None,
    key: str | None = None, key_id: str | None = None,
) -> dict[str, Any]:
    provider = str(payload.get("provider") or "")
    if provider not in PROVIDER_CONTRACTS:
        raise ValueError("unsupported_verification_provider")
    return sign_snapshot(
        kind="control_verification", tenant_id=tenant_id, payload=payload,
        source=f"{provider}/read-only-verification/v1", version=version,
        valid_from=valid_from, valid_to=valid_to, signer=signer, key=key, key_id=key_id,
    )


__all__ = [
    "PROVIDER_CONTRACTS", "ProviderContract", "build_verification_payload",
    "sign_provider_verification",
]
