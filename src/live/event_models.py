"""Lightweight event models for FAST_LIVE_MODE ingestion path.

These are intentionally minimal and decoupled from the heavier pipeline
objects so that live validation / pilot runs can ingest endpoint and
network telemetry without initializing the full orchestrator stack.
"""
from __future__ import annotations

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import time, uuid


class ProcInfo(BaseModel):
    name: Optional[str] = None
    parent: Optional[str] = None
    cmdline: Optional[str] = None


class NetInfo(BaseModel):
    dest_ip: Optional[str] = Field(None, alias="dest_ip")
    dest_port: Optional[int] = None
    proto: Optional[str] = None


class EndpointRawEvent(BaseModel):
    ts: Optional[float] = Field(None, description="Event timestamp (epoch seconds)")
    host: Optional[str] = None
    user: Optional[str] = None
    proc: Optional[ProcInfo] = None
    net: Optional[NetInfo] = None
    hash: Optional[str] = None
    tags: Optional[List[str]] = None
    id: Optional[str] = None

    def to_normalized(self) -> Dict[str, Any]:
        """Convert to normalized internal dict representation.

        Fields intentionally flattened to simplify correlation & export.
        """
        ts_val = self.ts if isinstance(self.ts, (int, float)) else time.time()
        norm = {
            'id': self.id or uuid.uuid4().hex,
            'ts': float(ts_val),
            'host': self.host or 'unknown_host',
            'user': self.user or 'unknown_user',
            'proc_name': (self.proc.name if self.proc else None) or 'unknown_proc',
            'parent_proc': (self.proc.parent if self.proc else None) or None,
            'cmdline': (self.proc.cmdline if self.proc else None) or None,
            'dest_ip': (self.net.dest_ip if self.net else None) or None,
            'dest_port': (self.net.dest_port if self.net else None) or None,
            'proto': (self.net.proto if self.net else None) or None,
            'hash': self.hash,
            'tags': list(self.tags) if self.tags else [],
            'source': 'endpoint_batch'
        }
        return norm


class NormalizedEvent(BaseModel):
    id: str
    ts: float
    host: str
    user: str
    proc_name: str
    parent_proc: Optional[str] = None
    cmdline: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    proto: Optional[str] = None
    hash: Optional[str] = None
    tags: list[str] = []
    source: str = 'endpoint_batch'

    @classmethod
    def from_raw(cls, raw: EndpointRawEvent) -> 'NormalizedEvent':
        data = raw.to_normalized()
        return cls(**data)  # type: ignore[arg-type]
