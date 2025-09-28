from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class TenantContext(BaseModel):
    tenant_id: str
    raw_header: Optional[str] = None


class IngestEvent(BaseModel):
    id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    process: Optional[Dict[str, Any]] = None
    parent_process: Optional[Dict[str, Any]] = None
    domain: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None


class DecisionRecord(BaseModel):
    event_id: str
    verdict: str
    confidence: float
    factors: List[str] = Field(default_factory=list)
    timestamp: float = Field(default_factory=lambda: time.time())
    tenant_id: Optional[str] = None


class DecisionResponse(BaseModel):
    event_id: str
    verdict: str
    confidence: float
    factors: List[str] = Field(default_factory=list)
    tenant_id: str


class AlertSnapshot(BaseModel):
    id: str
    verdict: str
    confidence: float
    factors: List[str]
    tenant_id: str
    ts: float
