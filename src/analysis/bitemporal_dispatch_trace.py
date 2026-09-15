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
import os
import sqlite3
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
    """Attach an outcome record to a stored decision and re-persist it."""
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
    # Re-persist so SQLiteDecisionTraceStore reflects the updated outcomes.
    # InMemoryDecisionTraceStore already holds a reference to the same object,
    # so put() is a no-op for the in-memory case (idempotent).
    try:
        store.put(decision)
    except Exception as exc:
        logger.warning('record_action_outcome: put() failed for %s: %s', decision_id, exc)
    return True


class SQLiteDecisionTraceStore:
    """File-persisted bitemporal decision trace backed by SQLite.

    Survives server restarts; required for TemporalRAG.retrieve_prior_decisions()
    to return anything on a fresh boot.  Schema mirrors InMemoryDecisionTraceStore
    but serialises DispatchDecision to JSON rows.

    Path: configured via JANUSEC_TRACE_DB env var or passed explicitly.
    """

    def __init__(self, path: str | None = None) -> None:
        self._path = path or os.getenv('JANUSEC_TRACE_DB', 'data/sessions/decision_trace.db')
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        # WAL mode: readers don't block writers; 5s busy timeout avoids SQLITE_BUSY
        self._conn.execute('PRAGMA journal_mode=WAL')
        self._conn.execute('PRAGMA busy_timeout=5000')
        self._conn.execute('''
            CREATE TABLE IF NOT EXISTS decisions (
                decision_id        TEXT PRIMARY KEY,
                tenant_id          TEXT NOT NULL,
                cluster_id         TEXT NOT NULL,
                persona            TEXT NOT NULL,
                transaction_time   TEXT NOT NULL,
                superseded_by      TEXT,
                payload_json       TEXT NOT NULL
            )
        ''')
        self._conn.execute(
            'CREATE INDEX IF NOT EXISTS ix_dec_cluster_persona '
            'ON decisions (tenant_id, cluster_id, persona, transaction_time)'
        )
        self._conn.commit()

    def _deserialise(self, row: tuple) -> DispatchDecision:
        d = json.loads(row[6])
        return DispatchDecision(
            decision_id=d['decision_id'],
            cluster_id=d['cluster_id'],
            persona=d['persona'],
            tenant_id=d['tenant_id'],
            valid_time_start=d.get('valid_time_start'),
            valid_time_end=d.get('valid_time_end'),
            transaction_time=d['transaction_time'],
            framework_version=d.get('framework_version', 'unknown'),
            evidence_row_indices=d.get('evidence_row_indices', []),
            evidence_content_hash=d.get('evidence_content_hash', ''),
            verdict=d.get('verdict'),
            confidence=d.get('confidence'),
            supersedes=d.get('supersedes', []),
            superseded_by=row[5],
            payload=d.get('payload', {}),
            action_outcomes=d.get('action_outcomes'),
        )

    def put(self, decision: DispatchDecision) -> None:
        blob = json.dumps(asdict(decision), default=str)
        with self._lock:
            self._conn.execute(
                'INSERT OR REPLACE INTO decisions '
                '(decision_id, tenant_id, cluster_id, persona, transaction_time, superseded_by, payload_json) '
                'VALUES (?, ?, ?, ?, ?, ?, ?)',
                (decision.decision_id, decision.tenant_id, decision.cluster_id,
                 decision.persona, decision.transaction_time, decision.superseded_by, blob),
            )
            for sid in decision.supersedes:
                self._conn.execute(
                    'UPDATE decisions SET superseded_by = ? WHERE decision_id = ?',
                    (decision.decision_id, sid),
                )
            self._conn.commit()

    def get(self, decision_id: str) -> Optional[DispatchDecision]:
        with self._lock:
            row = self._conn.execute(
                'SELECT * FROM decisions WHERE decision_id = ?', (decision_id,)
            ).fetchone()
        return self._deserialise(row) if row else None

    def find_active(self, cluster_id: str, persona: str, tenant_id: str) -> list[DispatchDecision]:
        with self._lock:
            rows = self._conn.execute(
                'SELECT * FROM decisions WHERE tenant_id=? AND cluster_id=? AND persona=? AND superseded_by IS NULL',
                (tenant_id, cluster_id, persona),
            ).fetchall()
        return [self._deserialise(r) for r in rows]

    def find_at_transaction_time(self, cluster_id: str, persona: str,
                                 tenant_id: str, as_of: str) -> list[DispatchDecision]:
        with self._lock:
            rows = self._conn.execute(
                'SELECT * FROM decisions WHERE tenant_id=? AND cluster_id=? AND persona=? '
                'AND transaction_time <= ?',
                (tenant_id, cluster_id, persona, as_of),
            ).fetchall()
        out: list[DispatchDecision] = []
        for r in rows:
            d = self._deserialise(r)
            if d.superseded_by is None:
                out.append(d)
            else:
                succ_row = self._conn.execute(
                    'SELECT transaction_time FROM decisions WHERE decision_id=?', (d.superseded_by,)
                ).fetchone()
                if succ_row and succ_row[0] > as_of:
                    out.append(d)
        return out


__all__ = [
    'DispatchDecision',
    'DecisionTraceStore',
    'InMemoryDecisionTraceStore',
    'SQLiteDecisionTraceStore',
    'trace_persona_dispatch',
    'find_superseded_decisions',
    'replay_state_at',
    'record_action_outcome',
]
