"""Bitemporal decision trace for persona dispatch.

Wraps every persona dispatch payload with bitemporal provenance:

    valid_time      — when the underlying evidence was actually true
    transaction_time — when JanuSec made this decision and recorded it

This makes dispatch defensible to regulators: "At the time we knew X,
here's what we decided. Later we learned Y, here's what we changed."
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional, Protocol

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
#  Decision record
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DispatchDecision:
    decision_id: str
    cluster_id: str
    persona: str
    tenant_id: str

    valid_time_start: Optional[str]
    valid_time_end: Optional[str]
    transaction_time: str

    framework_version: str
    evidence_row_indices: list[int]
    evidence_content_hash: str

    verdict: Optional[str]
    confidence: Optional[float]

    supersedes: list[str] = field(default_factory=list)
    superseded_by: Optional[str] = None

    payload: dict = field(default_factory=dict)
    action_outcomes: Optional[list[dict]] = None

    def to_dict(self) -> dict:
        return asdict(self)

    def is_active(self) -> bool:
        return self.superseded_by is None


# ─────────────────────────────────────────────────────────────────────────────
#  Trace store interface
# ─────────────────────────────────────────────────────────────────────────────

class DecisionTraceStore(Protocol):
    def put(self, decision: DispatchDecision) -> None: ...
    def get(self, decision_id: str) -> Optional[DispatchDecision]: ...
    def find_active(self, cluster_id: str, persona: str,
                    tenant_id: str) -> list[DispatchDecision]: ...
    def find_at_transaction_time(self, cluster_id: str, persona: str,
                                 tenant_id: str,
                                 as_of: str) -> list[DispatchDecision]: ...


# ─────────────────────────────────────────────────────────────────────────────
#  Reference in-memory implementation
# ─────────────────────────────────────────────────────────────────────────────

class InMemoryDecisionTraceStore:
    """Thread-safe reference implementation. Replace with Postgres/SQLite-WAL
    or your existing bitemporal store for production."""

    def __init__(self):
        self._lock = threading.RLock()
        self._by_id: dict[str, DispatchDecision] = {}
        self._by_cluster_persona: dict[tuple[str, str, str], list[str]] = {}

    def put(self, decision: DispatchDecision) -> None:
        with self._lock:
            self._by_id[decision.decision_id] = decision
            key = (decision.tenant_id, decision.cluster_id, decision.persona)
            self._by_cluster_persona.setdefault(key, []).append(decision.decision_id)
            for sid in decision.supersedes:
                prior = self._by_id.get(sid)
                if prior:
                    prior.superseded_by = decision.decision_id

    def get(self, decision_id: str) -> Optional[DispatchDecision]:
        with self._lock:
            return self._by_id.get(decision_id)

    def find_active(self, cluster_id: str, persona: str,
                    tenant_id: str) -> list[DispatchDecision]:
        with self._lock:
            ids = self._by_cluster_persona.get((tenant_id, cluster_id, persona), [])
            return [self._by_id[i] for i in ids
                    if self._by_id[i].is_active()]

    def find_at_transaction_time(self, cluster_id: str, persona: str,
                                 tenant_id: str,
                                 as_of: str) -> list[DispatchDecision]:
        with self._lock:
            ids = self._by_cluster_persona.get((tenant_id, cluster_id, persona), [])
            out: list[DispatchDecision] = []
            for i in ids:
                d = self._by_id[i]
                if d.transaction_time > as_of:
                    continue
                if d.superseded_by is None:
                    out.append(d)
                else:
                    succ = self._by_id.get(d.superseded_by)
                    if succ and succ.transaction_time > as_of:
                        out.append(d)
            return out


# ─────────────────────────────────────────────────────────────────────────────
#  Decision construction
# ─────────────────────────────────────────────────────────────────────────────

def _row_timestamp(row: dict) -> Optional[str]:
    for f in ('timestamp', 'eventTime', 'published', 'CreationTime',
              'start_time', '@timestamp', 'ts'):
        v = row.get(f)
        if isinstance(v, str) and v:
            return v
    return None


def _evidence_content_hash(rows: list[dict]) -> str:
    canon: list[Any] = []
    for r in rows or []:
        canon.append({
            'row_index': r.get('row_index') or r.get('row_number'),
            'timestamp': _row_timestamp(r),
            '_source': r.get('_source') or r.get('source'),
            'event': (r.get('eventName') or r.get('event_simpleName') or
                      r.get('Operation') or r.get('eventType') or ''),
            'description': (r.get('description') or r.get('analyst_notes')
                            or r.get('query_text') or r.get('command_line') or '')[:500],
        })
    blob = json.dumps(canon, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return hashlib.sha256(blob).hexdigest()


def _decision_id(cluster_id: str, persona: str, tenant_id: str,
                 transaction_time: str, content_hash: str) -> str:
    h = hashlib.sha256(
        f'{tenant_id}|{cluster_id}|{persona}|{transaction_time}|{content_hash}'.encode('utf-8')
    ).hexdigest()
    return f'dec-{h[:24]}'


def trace_persona_dispatch(*,
                           payload: dict,
                           narrative: dict,
                           rows: list[dict],
                           cluster_id: str,
                           tenant_id: str,
                           framework_version: str = 'unknown',
                           supersedes: Optional[list[str]] = None,
                           transaction_time: Optional[str] = None) -> DispatchDecision:
    """Wrap a persona dispatch payload with bitemporal provenance."""
    rows = rows or []
    timestamps = [t for t in (_row_timestamp(r) for r in rows) if t]
    valid_start = min(timestamps) if timestamps else None
    valid_end = max(timestamps) if timestamps else None

    tt = transaction_time or datetime.now(timezone.utc).isoformat()
    content_hash = _evidence_content_hash(rows)
    persona = payload.get('persona') or 'unknown'

    return DispatchDecision(
        decision_id=_decision_id(cluster_id, persona, tenant_id, tt, content_hash),
        cluster_id=cluster_id,
        persona=persona,
        tenant_id=tenant_id,
        valid_time_start=valid_start,
        valid_time_end=valid_end,
        transaction_time=tt,
        framework_version=framework_version,
        evidence_row_indices=sorted({
            int(r['row_index']) for r in rows
            if isinstance(r.get('row_index'), (int, str)) and str(r.get('row_index')).isdigit()
        }),
        evidence_content_hash=content_hash,
        verdict=narrative.get('verdict'),
        confidence=narrative.get('confidence'),
        supersedes=list(supersedes or []),
        payload=payload,
    )


def find_superseded_decisions(*,
                              store: DecisionTraceStore,
                              cluster_id: str,
                              persona: str,
                              tenant_id: str) -> list[DispatchDecision]:
    """Find all currently-active decisions for this cluster+persona that a
    new decision will supersede."""
    return store.find_active(cluster_id=cluster_id, persona=persona,
                             tenant_id=tenant_id)


def replay_state_at(*,
                    store: DecisionTraceStore,
                    cluster_id: str,
                    persona: str,
                    tenant_id: str,
                    as_of: str) -> dict:
    """The 'as we knew it then' query for audit walk-throughs."""
    decisions = store.find_at_transaction_time(
        cluster_id=cluster_id, persona=persona,
        tenant_id=tenant_id, as_of=as_of,
    )
    if not decisions:
        return {'persona': persona, 'as_of': as_of,
                'decisions': [], 'note': 'no decisions on record at this transaction time'}
    decisions.sort(key=lambda d: d.transaction_time, reverse=True)
    return {
        'persona': persona,
        'as_of': as_of,
        'active_decision': decisions[0].to_dict(),
        'all_active_count': len(decisions),
    }


def record_action_outcome(*,
                          store: DecisionTraceStore,
                          decision_id: str,
                          action_id: str,
                          outcome: str,
                          executed_by: Optional[str] = None,
                          executed_at: Optional[str] = None,
                          tool_response: Optional[dict] = None) -> bool:
    """Attach an outcome record to a stored decision."""
    decision = store.get(decision_id)
    if not decision:
        logger.warning('record_action_outcome: decision %s not found', decision_id)
        return False
    if decision.action_outcomes is None:
        decision.action_outcomes = []
    decision.action_outcomes.append({
        'action_id': action_id,
        'outcome': outcome,
        'executed_by': executed_by,
        'executed_at': executed_at or datetime.now(timezone.utc).isoformat(),
        'tool_response': tool_response or {},
    })
    return True


__all__ = [
    'DispatchDecision',
    'DecisionTraceStore',
    'InMemoryDecisionTraceStore',
    'trace_persona_dispatch',
    'find_superseded_decisions',
    'replay_state_at',
    'record_action_outcome',
]
