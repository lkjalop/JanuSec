"""Persistent decision lifecycle store.

Every security decision — from first detection through triage, disposition,
escalation, and final resolution — is recorded here with an append-only
audit trail. Survives server restarts. Meets compliance requirements for
evidence retention (each transition is a separate JSONL record with
monotonic timestamps — records are never mutated in place).

Env vars:
  DECISION_LIFECYCLE_PATH   — JSONL file (default: data/decision_lifecycle.jsonl)
  DECISION_LIFECYCLE_MAX    — max entries kept in-memory (default: 5000)

State machine:
  pending → cleared | actioned | escalated | false_positive
  escalated → pending (demoted/new info) | actioned | cleared
  cleared → pending (reopened on new evidence)
  actioned → closed
  false_positive → pending (reversed by analyst)
  *any* → correlated_promoted | isolated_demoted (correlation state changes)

Every transition records: who, when, why (free text), from_state, to_state,
and optional correlation_change (isolated→correlated or correlated→isolated).
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Valid states
# ---------------------------------------------------------------------------
VALID_STATES = frozenset({
    'pending',              # initial: awaiting analyst review
    'cleared',              # analyst reviewed — benign / no action
    'actioned',             # analyst took action (containment, notify, etc.)
    'escalated',            # promoted to higher tier / severity
    'false_positive',       # confirmed FP — tuning candidate
    'closed',               # final: no further action required
})

VALID_CORRELATION_STATES = frozenset({'isolated', 'correlated'})


# ---------------------------------------------------------------------------
# Lifecycle record
# ---------------------------------------------------------------------------
@dataclass
class DecisionRecord:
    id: str                          # unique record id
    event_id: str                    # links to the assessment / event
    state: str                       # current lifecycle state
    previous_state: str              # state before this transition
    correlation_state: str           # 'isolated' or 'correlated'
    previous_correlation_state: str  # '' or previous
    disposition: str                 # from event_disposition.classify()
    priority: str                    # P1/P2/P3/awareness/admin
    actor: str                       # who made this transition
    reason: str                      # free text — why
    factors: list                    # factor list snapshot at transition time
    triage_score: float
    timestamp: float                 # monotonic epoch
    escalation_plan: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)  # arbitrary extras


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------
def _store_path() -> str:
    return os.getenv('DECISION_LIFECYCLE_PATH',
                     os.path.join('data', 'decision_lifecycle.jsonl'))


def _max_entries() -> int:
    try:
        return int(os.getenv('DECISION_LIFECYCLE_MAX', '5000'))
    except Exception:
        return 5000


def _load_from_disk() -> list[dict[str, Any]]:
    path = _store_path()
    if not os.path.exists(path):
        return []
    entries: list[dict[str, Any]] = []
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        pass
    except Exception:
        pass
    return entries[-_max_entries():]


def _append_to_disk(record: dict[str, Any]) -> None:
    path = _store_path()
    try:
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        with open(path, 'a', encoding='utf-8') as fh:
            fh.write(json.dumps(record, default=str) + '\n')
    except Exception:
        pass


# ---------------------------------------------------------------------------
# In-memory index  (rebuilt from disk on import)
# ---------------------------------------------------------------------------
class DecisionLifecycleStore:
    """Thread-safe, file-backed decision lifecycle store.

    Maintains:
      - _records: full append-only log  (each transition is a record)
      - _current: event_id → latest DecisionRecord  (fast lookup)
      - _history: event_id → [DecisionRecord, ...]  (full audit trail per event)
    """

    def __init__(self, initial: list[dict[str, Any]] | None = None):
        self._records: list[dict[str, Any]] = list(initial or [])
        self._current: dict[str, dict[str, Any]] = {}
        self._history: dict[str, list[dict[str, Any]]] = {}
        # Build indices from loaded data
        for rec in self._records:
            eid = rec.get('event_id', '')
            self._current[eid] = rec
            self._history.setdefault(eid, []).append(rec)

    # ── Transition ──────────────────────────────────────────────────
    def transition(
        self,
        event_id: str,
        new_state: str,
        *,
        actor: str = 'system',
        reason: str = '',
        disposition: str = '',
        priority: str = '',
        factors: list | None = None,
        triage_score: float = 0.0,
        correlation_state: str = '',
        escalation_plan: dict | None = None,
        metadata: dict | None = None,
    ) -> dict[str, Any]:
        """Record a state transition for an event. Returns the new record dict."""
        with _LOCK:
            prev = self._current.get(event_id, {})
            prev_state = prev.get('state', '')
            prev_corr = prev.get('correlation_state', '')

            rec = asdict(DecisionRecord(
                id=str(uuid.uuid4()),
                event_id=event_id,
                state=new_state,
                previous_state=prev_state,
                correlation_state=correlation_state or prev_corr or 'isolated',
                previous_correlation_state=prev_corr,
                disposition=disposition or prev.get('disposition', ''),
                priority=priority or prev.get('priority', ''),
                actor=actor,
                reason=reason,
                factors=list(factors or prev.get('factors', [])),
                triage_score=triage_score or prev.get('triage_score', 0.0),
                timestamp=time.time(),
                escalation_plan=escalation_plan or prev.get('escalation_plan', {}),
                metadata=metadata or {},
            ))

            self._records.append(rec)
            self._current[event_id] = rec
            self._history.setdefault(event_id, []).append(rec)

            # Trim in-memory
            cap = _max_entries()
            if len(self._records) > cap:
                self._records = self._records[-cap:]

        _append_to_disk(rec)
        return rec

    # ── Correlation change ──────────────────────────────────────────
    def change_correlation(
        self,
        event_id: str,
        new_correlation: str,
        *,
        actor: str = 'system',
        reason: str = '',
    ) -> dict[str, Any]:
        """Record an isolated↔correlated promotion/demotion."""
        with _LOCK:
            prev = self._current.get(event_id, {})
        return self.transition(
            event_id,
            new_state=prev.get('state', 'pending'),
            actor=actor,
            reason=reason,
            correlation_state=new_correlation,
        )

    # ── Queries ─────────────────────────────────────────────────────
    def get_current(self, event_id: str) -> dict[str, Any] | None:
        with _LOCK:
            return self._current.get(event_id)

    def get_history(self, event_id: str) -> list[dict[str, Any]]:
        with _LOCK:
            return list(self._history.get(event_id, []))

    def list_by_state(self, state: str, limit: int = 200) -> list[dict[str, Any]]:
        with _LOCK:
            return [r for r in reversed(list(self._current.values()))
                    if r.get('state') == state][:limit]

    def list_recent(self, limit: int = 200) -> list[dict[str, Any]]:
        with _LOCK:
            return list(reversed(list(self._current.values())))[:limit]

    def summary_stats(self) -> dict[str, Any]:
        """Return counts by state and correlation state."""
        with _LOCK:
            states: dict[str, int] = {}
            corr: dict[str, int] = {}
            dispositions: dict[str, int] = {}
            priorities: dict[str, int] = {}
            for r in self._current.values():
                s = r.get('state', 'unknown')
                c = r.get('correlation_state', 'unknown')
                d = r.get('disposition', 'unknown')
                p = r.get('priority', 'unknown')
                states[s] = states.get(s, 0) + 1
                corr[c] = corr.get(c, 0) + 1
                dispositions[d] = dispositions.get(d, 0) + 1
                priorities[p] = priorities.get(p, 0) + 1
            total = len(self._current)
            total_transitions = len(self._records)
        return {
            'total_events': total,
            'total_transitions': total_transitions,
            'by_state': states,
            'by_correlation': corr,
            'by_disposition': dispositions,
            'by_priority': priorities,
        }

    def count(self) -> int:
        with _LOCK:
            return len(self._current)

    def all_records(self) -> list[dict[str, Any]]:
        """Full append-only log (for compliance export)."""
        with _LOCK:
            return list(self._records)


# ---------------------------------------------------------------------------
# Module-level singleton (loaded from disk on import)
# ---------------------------------------------------------------------------
DECISION_LIFECYCLE: DecisionLifecycleStore = DecisionLifecycleStore(_load_from_disk())
