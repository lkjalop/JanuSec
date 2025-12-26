"""Lightweight event models for FAST_LIVE_MODE ingestion path.

These are intentionally minimal and decoupled from the heavier pipeline
objects so that live validation / pilot runs can ingest endpoint and
network telemetry without initializing the full orchestrator stack.
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ProcInfo(BaseModel):  # type: ignore[misc]
    name: str | None = None
    parent: str | None = None
    cmdline: str | None = None


class NetInfo(BaseModel):  # type: ignore[misc]
    dest_ip: str | None = Field(None, alias="dest_ip")
    dest_port: int | None = None
    proto: str | None = None


class EndpointRawEvent(BaseModel):  # type: ignore[misc]
    ts: float | None = Field(None, description="Event timestamp (epoch seconds)")
    host: str | None = None
    user: str | None = None
    proc: ProcInfo | None = None
    net: NetInfo | None = None
    hash: str | None = None
    tags: list[str] | None = None
    id: str | None = None

    def to_normalized(self) -> dict[str, Any]:
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


class NormalizedEvent(BaseModel):  # type: ignore[misc]
    id: str
    ts: float
    host: str
    user: str
    proc_name: str
    parent_proc: str | None = None
    cmdline: str | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    proto: str | None = None
    hash: str | None = None
    tags: list[str] = []
    source: str = 'endpoint_batch'

    @classmethod
    def from_raw(cls, raw: EndpointRawEvent) -> NormalizedEvent:
        data = raw.to_normalized()
        return cls(**data)


class EmailEvent(BaseModel):  # type: ignore[misc]
    """Lightweight email event used by collectors and enrichment stages.

    Fields are intentionally simple: headers/body plus common metadata
    so downstream enrichment can run without heavy dependencies.
    """
    timestamp: float | None = Field(None, description="Event timestamp (epoch seconds)")
    tenant_id: str | None = None
    source: str | None = None  # office365 | gmail | imap
    sender: str | None = None
    sender_display_name: str | None = None
    recipients: list[str] | None = None
    subject: str | None = None
    has_attachments: bool | None = None
    headers: dict[str, Any] | None = None
    body_preview: str | None = None
    message_id: str | None = None
    raw_event: dict[str, Any] | None = None

    def to_envelope(self) -> dict[str, Any]:
        return {
            'timestamp': float(self.timestamp or 0.0),
            'tenant_id': self.tenant_id,
            'source': self.source,
            'sender': self.sender,
            'sender_display_name': self.sender_display_name,
            'recipients': list(self.recipients or []),
            'subject': self.subject,
            'has_attachments': bool(self.has_attachments or False),
            'headers': dict(self.headers or {}),
            'body_preview': self.body_preview,
            'message_id': self.message_id,
        }
