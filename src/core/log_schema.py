from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional
import uuid


def _parse_iso(ts: str) -> datetime:
    # accept trailing Z
    try:
        if ts.endswith("Z"):
            ts = ts[:-1]
        return datetime.fromisoformat(ts)
    except Exception:
        raise ValueError(f"invalid timestamp: {ts}")


@dataclass
class CollectorProvenance:
    collector_id: str
    collector_version: Optional[str] = None
    collector_hostname: Optional[str] = None
    collector_pid: Optional[int] = None
    collector_start_ts: Optional[str] = None
    raw_path: Optional[str] = None
    raw_checksum: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CanonicalEvent:
    # Core fields
    id: str
    tenant_id: str
    timestamp: str
    event_type: str
    source: str
    source_type: str

    # Optional rich context
    host: Optional[str] = None
    ip: Optional[str] = None
    user: Optional[str] = None
    payload: Dict[str, Any] = field(default_factory=dict)

    # Detection / analysis fields
    factors: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    confidence: Optional[float] = None

    # Provenance
    provenance: Optional[Dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Lightweight schema validator — intentionally strict on required keys but permissive on payload
REQUIRED_EVENT_KEYS = [
    "id",
    "tenant_id",
    "timestamp",
    "event_type",
    "source",
    "source_type",
]


def validate_event(obj: Dict[str, Any]) -> (bool, List[str]):
    """
    Validate that `obj` conforms to the minimal canonical event contract.

    Returns: (is_valid, errors)
    """
    errors: List[str] = []

    if not isinstance(obj, dict):
        return False, ["event must be a JSON object/dict"]

    for k in REQUIRED_EVENT_KEYS:
        if k not in obj:
            errors.append(f"missing required key: {k}")

    # timestamp parse check
    if "timestamp" in obj:
        try:
            _parse_iso(obj["timestamp"])  # will raise on error
        except Exception as e:
            errors.append(str(e))

    # id sanity
    if "id" in obj:
        try:
            uuid.UUID(obj["id"])
        except Exception:
            errors.append("id must be a valid UUID string")

    # tenant_id type
    if "tenant_id" in obj and not isinstance(obj["tenant_id"], str):
        errors.append("tenant_id must be a string")

    # optional provenance shape check
    if "provenance" in obj and obj["provenance"] is not None:
        if not isinstance(obj["provenance"], dict):
            errors.append("provenance must be an object/dict if provided")

    return (len(errors) == 0), errors


def make_event(tenant_id: str, event_type: str, source: str, source_type: str, **kwargs) -> Dict[str, Any]:
    """Convenience builder for tests and ingestion code"""
    e = CanonicalEvent(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        timestamp=datetime.utcnow().isoformat() + "Z",
        event_type=event_type,
        source=source,
        source_type=source_type,
        host=kwargs.get("host"),
        ip=kwargs.get("ip"),
        user=kwargs.get("user"),
        payload=kwargs.get("payload", {}),
        factors=kwargs.get("factors", []),
        tags=kwargs.get("tags", []),
        confidence=kwargs.get("confidence"),
        provenance=(kwargs.get("provenance") or CollectorProvenance(collector_id="unknown").to_dict()),
    )
    return e.to_dict()
