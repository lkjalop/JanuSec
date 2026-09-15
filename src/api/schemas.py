from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class TenantContext(BaseModel):  # type: ignore[misc]
    tenant_id: str
    raw_header: str | None = None
    model_config = ConfigDict(extra='forbid')


class IngestEvent(BaseModel):  # type: ignore[misc]
    id: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    process: dict[str, Any] | None = None
    parent_process: dict[str, Any] | None = None
    domain: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    # Allow extra vendor/sensor fields (e.g. 'event_type') so ingestion
    # accepts a variety of telemetry payloads used by tests and real
    # integrations without rejecting unknown top-level keys.
    model_config = ConfigDict(extra='allow')


class CanonicalEvent(BaseModel):  # type: ignore[misc]
    """Canonical normalized event for downstream correlation & scoring.

    This model captures the minimal normalized fields required for early
    customer ingestion readiness and FP reduction workflows. It intentionally
    allows extra fields for future enrichment while guarding against silently
    dropped keys.
    """
    timestamp: float | None = None
    source_type: str | None = None
    ip_src: str | None = None
    ip_dst: str | None = None
    user: str | None = None
    host: str | None = None
    process: str | None = None
    file_hash: str | None = None
    domain: str | None = None
    action: str | None = None
    outcome: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)
    model_config = ConfigDict(extra='allow')


class DecisionRecord(BaseModel):  # type: ignore[misc]
    event_id: str
    verdict: str
    confidence: float
    factors: list[str] = Field(default_factory=list)
    correlation_insights: List[Dict[str, Any]] = Field(default_factory=list)
    timestamp: float = Field(default_factory=lambda: time.time())
    tenant_id: str | None = None
    processing_time_ms: float | None = None

    model_config = ConfigDict(extra='allow')


class DecisionResponse(BaseModel):  # type: ignore[misc]
    event_id: str
    verdict: str
    confidence: float
    factors: list[str] = Field(default_factory=list)
    correlation_insights: List[Dict[str, Any]] | None = None
    tenant_id: str


class AlertSnapshot(BaseModel):  # type: ignore[misc]
    id: str
    verdict: str
    confidence: float
    factors: list[str]
    tenant_id: str
    ts: float
