"""Versioned core data schemas for events, decisions, incidents.

Provides forward-compatible, explicit Pydantic models with a lightweight
registry so future migrations can branch on `schema_version`.
"""
from __future__ import annotations

from pydantic import BaseModel, Field, constr
from typing import List, Dict, Any, Optional
import datetime as _dt

CURRENT_EVENT_VERSION = 1
CURRENT_DECISION_VERSION = 1
CURRENT_INCIDENT_VERSION = 1

class EventV1(BaseModel):
    schema_version: int = Field(CURRENT_EVENT_VERSION, const=True)
    id: constr(min_length=1)  # noqa
    tenant_id: str = 'default'
    received_at: _dt.datetime = Field(default_factory=lambda: _dt.datetime.utcnow().replace(tzinfo=_dt.timezone.utc))
    raw: Dict[str, Any]
    normalized: Dict[str, Any] = Field(default_factory=dict)
    source: Optional[str] = None

class DecisionV1(BaseModel):
    schema_version: int = Field(CURRENT_DECISION_VERSION, const=True)
    id: constr(min_length=1)  # noqa
    event_id: str
    tenant_id: str = 'default'
    decided_at: _dt.datetime = Field(default_factory=lambda: _dt.datetime.utcnow().replace(tzinfo=_dt.timezone.utc))
    verdict: str
    confidence: float
    factors: List[str] = Field(default_factory=list)
    techniques: Dict[str, List[str]] = Field(default_factory=dict)
    reasons: Dict[str, Any] = Field(default_factory=dict)

class IncidentV1(BaseModel):
    schema_version: int = Field(CURRENT_INCIDENT_VERSION, const=True)
    id: constr(min_length=1)  # noqa
    tenant_id: str = 'default'
    created_at: _dt.datetime = Field(default_factory=lambda: _dt.datetime.utcnow().replace(tzinfo=_dt.timezone.utc))
    related_event_ids: List[str] = Field(default_factory=list)
    decision_ids: List[str] = Field(default_factory=list)
    severity: str = 'medium'
    status: str = 'open'
    summary: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    # Optional attack subgraph produced by HopGraph.reconstruct_attack
    attack_subgraph: Optional[Dict[str, Any]] = None

# Registries (future versions can be appended without breaking callers)
EVENT_SCHEMAS = {1: EventV1}
DECISION_SCHEMAS = {1: DecisionV1}
INCIDENT_SCHEMAS = {1: IncidentV1}

def load_event(data: Dict[str, Any]):
    v = int(data.get('schema_version') or CURRENT_EVENT_VERSION)
    model = EVENT_SCHEMAS.get(v)
    if not model:
        raise ValueError(f"Unsupported event schema version {v}")
    return model(**data)

def load_decision(data: Dict[str, Any]):
    v = int(data.get('schema_version') or CURRENT_DECISION_VERSION)
    model = DECISION_SCHEMAS.get(v)
    if not model:
        raise ValueError(f"Unsupported decision schema version {v}")
    return model(**data)

def load_incident(data: Dict[str, Any]):
    v = int(data.get('schema_version') or CURRENT_INCIDENT_VERSION)
    model = INCIDENT_SCHEMAS.get(v)
    if not model:
        raise ValueError(f"Unsupported incident schema version {v}")
    return model(**data)

__all__ = [
    'EventV1','DecisionV1','IncidentV1',
    'load_event','load_decision','load_incident',
    'CURRENT_EVENT_VERSION','CURRENT_DECISION_VERSION','CURRENT_INCIDENT_VERSION'
]