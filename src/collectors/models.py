from __future__ import annotations
from pydantic import BaseModel, Field, ConfigDict, field_serializer
from typing import Optional, Dict, Any
from datetime import datetime


class CanonicalNetworkEvent(BaseModel):
    # Common fields for syslog/flow events normalized into pipeline-friendly schema
    ts: datetime = Field(..., description='Event timestamp (UTC)')
    source: str = Field(..., description='Original source identifier (ip or exporter)')
    tenant_id: Optional[str] = Field(None, description='Tenant id mapping')
    device_vendor: Optional[str] = Field(None)
    device_product: Optional[str] = Field(None)
    device_version: Optional[str] = Field(None)
    message: Optional[str] = Field(None)
    raw: Optional[Dict[str, Any]] = Field(default_factory=dict)
    # Network flow fields (optional)
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    proto: Optional[int] = None
    bytes: Optional[int] = None
    packets: Optional[int] = None
    flow_start: Optional[datetime] = None
    flow_end: Optional[datetime] = None
    sampling_ratio: Optional[float] = None

    model_config = ConfigDict(arbitrary_types_allowed=True)

    @field_serializer('ts', 'flow_start', 'flow_end', when_used='json')
    def _serialize_dt(self, value: datetime | None):
        return value.isoformat() if isinstance(value, datetime) else value
