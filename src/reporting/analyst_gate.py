"""Human-gated analyst layer between Tier 1 triage and Tier 2 deep analysis.

This module implements the "analyst gate" — a mandatory human checkpoint
for P1/P2 alerts before expensive Tier-2 LLM calls, persona generation,
or containment actions are triggered.

Flow::

    Alerts → Tier-1 Triage → tiered_triage (P1-P4 scoring)
                ↓
        ┌───────────────────────────────────────┐
        │  ANALYST GATE (this module)            │
        │  - P1/P2 require explicit approval     │
        │  - P3/P4 auto-approved (configurable)  │
        │  - Timeout auto-escalates to SOC lead  │
        │  - Enriches with analyst notes/tags    │
        └───────────────────────────────────────┘
                ↓ (approved)
        Tier-2 RAG / Persona Generation / Containment Actions

Gate states:
  - PENDING:   awaiting analyst action
  - APPROVED:  analyst confirmed; proceed to Tier-2
  - REJECTED:  analyst marked false-positive; suppress
  - ESCALATED: time-expired; auto-escalated to SOC lead
  - DEFERRED:  analyst requested more context; on-demand fetch triggered

Usage (API layer)::

    gate = AnalystGate()
    gate.submit(alert_id, tier='P1', scored_alert=sa, analyst_pool=['soc1','soc2'])
    # ... analyst clicks approve in UI ...
    gate.approve(alert_id, analyst='soc1', notes='confirmed C2 beacon')
    # check:
    status = gate.status(alert_id)
    # status.state == 'APPROVED'
"""
from __future__ import annotations

import logging
import time
import threading
import json
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
import os

logger = logging.getLogger(__name__)


class GateState(str, Enum):
    PENDING = 'PENDING'
    APPROVED = 'APPROVED'
    REJECTED = 'REJECTED'
    ESCALATED = 'ESCALATED'
    DEFERRED = 'DEFERRED'


@dataclass
class GateEntry:
    """Single gated alert."""
    alert_id: str
    tier: str
    state: GateState = GateState.PENDING
    submitted_ts: float = field(default_factory=time.time)
    resolved_ts: Optional[float] = None
    analyst: Optional[str] = None
    notes: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    analyst_pool: List[str] = field(default_factory=list)
    escalation_target: Optional[str] = None
    priority_score: float = 0.0
    context_requests: List[str] = field(default_factory=list)

    # Enrichment attached by the analyst during review
    analyst_factors_added: List[str] = field(default_factory=list)
    analyst_factors_removed: List[str] = field(default_factory=list)
    analyst_confidence_override: Optional[float] = None


@dataclass
class GateConfig:
    """Configuration for the analyst gate."""
    # Tiers that require human approval (others auto-approve)
    gated_tiers: List[str] = field(default_factory=lambda: ['P1', 'P2'])

    # Seconds before auto-escalation (0 = disabled)
    escalation_timeout_seconds: int = 900  # 15 min

    # Target for auto-escalation
    default_escalation_target: str = 'soc_lead'

    # Auto-approve P3/P4 (bypass gate)
    auto_approve_lower_tiers: bool = True

    # Max pending entries (circuit breaker: reject new if full)
    max_pending: int = 500


class AnalystGate:
    """In-memory analyst gate.

    Production deployments should back this with Redis or a DB table;
    this implementation is suitable for single-tenant self-hosted installs
    and demo/dev usage.
    """

    def __init__(self, config: GateConfig | None = None):
        self.config = config or GateConfig()
        self._entries: Dict[str, GateEntry] = {}
        self._lock = threading.Lock()
        configured_path = os.getenv('ANALYST_GATE_STATE_PATH')
        self._persistence_enabled = not ('PYTEST_CURRENT_TEST' in os.environ and not configured_path)
        self._persist_path = Path(configured_path or 'data/state/analyst_gate.json')
        if self._persistence_enabled:
            self._load_state()

    def _serialize_entry(self, entry: GateEntry) -> Dict[str, Any]:
        return {
            'alert_id': entry.alert_id,
            'tier': entry.tier,
            'state': entry.state.value,
            'submitted_ts': entry.submitted_ts,
            'resolved_ts': entry.resolved_ts,
            'analyst': entry.analyst,
            'notes': entry.notes,
            'tags': list(entry.tags),
            'analyst_pool': list(entry.analyst_pool),
            'escalation_target': entry.escalation_target,
            'priority_score': entry.priority_score,
            'context_requests': list(entry.context_requests),
            'analyst_factors_added': list(entry.analyst_factors_added),
            'analyst_factors_removed': list(entry.analyst_factors_removed),
            'analyst_confidence_override': entry.analyst_confidence_override,
        }

    def _persist_state(self) -> None:
        if not self._persistence_enabled:
            return
        try:
            self._persist_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                'entries': {
                    alert_id: self._serialize_entry(entry)
                    for alert_id, entry in self._entries.items()
                }
            }
            self._persist_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding='utf-8')
        except Exception:
            logger.warning('Failed to persist analyst gate state', exc_info=True)

    def _load_state(self) -> None:
        if not self._persistence_enabled:
            return
        try:
            if not self._persist_path.exists():
                return
            payload = json.loads(self._persist_path.read_text(encoding='utf-8'))
            entries = payload.get('entries') if isinstance(payload, dict) else {}
            if not isinstance(entries, dict):
                return
            for alert_id, raw in entries.items():
                if not isinstance(raw, dict):
                    continue
                try:
                    self._entries[str(alert_id)] = GateEntry(
                        alert_id=str(raw.get('alert_id') or alert_id),
                        tier=str(raw.get('tier') or 'P3'),
                        state=GateState(str(raw.get('state') or GateState.PENDING.value)),
                        submitted_ts=float(raw.get('submitted_ts') or time.time()),
                        resolved_ts=float(raw['resolved_ts']) if raw.get('resolved_ts') is not None else None,
                        analyst=raw.get('analyst'),
                        notes=raw.get('notes'),
                        tags=list(raw.get('tags') or []),
                        analyst_pool=list(raw.get('analyst_pool') or []),
                        escalation_target=raw.get('escalation_target'),
                        priority_score=float(raw.get('priority_score') or 0.0),
                        context_requests=list(raw.get('context_requests') or []),
                        analyst_factors_added=list(raw.get('analyst_factors_added') or []),
                        analyst_factors_removed=list(raw.get('analyst_factors_removed') or []),
                        analyst_confidence_override=(
                            float(raw['analyst_confidence_override'])
                            if raw.get('analyst_confidence_override') is not None else None
                        ),
                    )
                except Exception:
                    continue
        except Exception:
            logger.warning('Failed to load analyst gate state', exc_info=True)

    # ------------------------------------------------------------------
    # Submission
    # ------------------------------------------------------------------

    def submit(
        self,
        alert_id: str,
        tier: str,
        priority_score: float = 0.0,
        analyst_pool: List[str] | None = None,
        context: Dict[str, Any] | None = None,
    ) -> GateEntry:
        """Submit an alert for analyst gating.

        If the tier is not in ``gated_tiers``, the entry is auto-approved.
        Returns the new or existing GateEntry.
        """
        with self._lock:
            if alert_id in self._entries:
                return self._entries[alert_id]

            entry = GateEntry(
                alert_id=alert_id,
                tier=tier,
                priority_score=priority_score,
                analyst_pool=analyst_pool or [],
            )

            # Auto-approve lower tiers
            if self.config.auto_approve_lower_tiers and tier not in self.config.gated_tiers:
                entry.state = GateState.APPROVED
                entry.resolved_ts = time.time()
                entry.notes = 'auto-approved (lower tier)'

            # Circuit breaker: reject if too many pending
            pending_count = sum(
                1 for e in self._entries.values() if e.state == GateState.PENDING
            )
            if pending_count >= self.config.max_pending and entry.state == GateState.PENDING:
                logger.warning(
                    'Analyst gate at capacity (%d pending); auto-approving %s',
                    pending_count, alert_id,
                )
                entry.state = GateState.APPROVED
                entry.resolved_ts = time.time()
                entry.notes = 'auto-approved (gate capacity exceeded)'

            self._entries[alert_id] = entry
            self._persist_state()
            return entry

    # ------------------------------------------------------------------
    # Analyst actions
    # ------------------------------------------------------------------

    def approve(
        self,
        alert_id: str,
        analyst: str,
        notes: str = '',
        tags: List[str] | None = None,
        confidence_override: float | None = None,
        factors_added: List[str] | None = None,
        factors_removed: List[str] | None = None,
    ) -> GateEntry:
        """Analyst approves the alert for Tier-2 processing."""
        with self._lock:
            entry = self._entries.get(alert_id)
            if not entry:
                raise KeyError(f'No gate entry for {alert_id}')
            entry.state = GateState.APPROVED
            entry.resolved_ts = time.time()
            entry.analyst = analyst
            entry.notes = notes
            entry.tags = tags or entry.tags
            entry.analyst_confidence_override = confidence_override
            entry.analyst_factors_added = factors_added or []
            entry.analyst_factors_removed = factors_removed or []
            self._persist_state()
            return entry

    def reject(
        self,
        alert_id: str,
        analyst: str,
        notes: str = '',
        tags: List[str] | None = None,
    ) -> GateEntry:
        """Analyst marks alert as false positive / suppress."""
        with self._lock:
            entry = self._entries.get(alert_id)
            if not entry:
                raise KeyError(f'No gate entry for {alert_id}')
            entry.state = GateState.REJECTED
            entry.resolved_ts = time.time()
            entry.analyst = analyst
            entry.notes = notes
            entry.tags = tags or entry.tags
            self._persist_state()
            return entry

    def defer(
        self,
        alert_id: str,
        analyst: str,
        context_requests: List[str] | None = None,
        notes: str = '',
    ) -> GateEntry:
        """Analyst requests more context before deciding.

        ``context_requests`` is a list of on-demand fetch hints, e.g.
        ['zeek:dns', 'sysmon:process', 'pcap:host=10.0.0.5'].
        The API layer should trigger the corresponding on-demand fetchers.
        """
        with self._lock:
            entry = self._entries.get(alert_id)
            if not entry:
                raise KeyError(f'No gate entry for {alert_id}')
            entry.state = GateState.DEFERRED
            entry.analyst = analyst
            entry.notes = notes
            entry.context_requests = context_requests or []
            self._persist_state()
            return entry

    def resubmit(self, alert_id: str) -> GateEntry:
        """Move a DEFERRED entry back to PENDING after new context arrives."""
        with self._lock:
            entry = self._entries.get(alert_id)
            if not entry:
                raise KeyError(f'No gate entry for {alert_id}')
            entry.state = GateState.PENDING
            entry.context_requests = []
            self._persist_state()
            return entry

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def status(self, alert_id: str) -> GateEntry | None:
        return self._entries.get(alert_id)

    def pending(self) -> List[GateEntry]:
        """All PENDING entries, sorted by priority descending."""
        with self._lock:
            return sorted(
                [e for e in self._entries.values() if e.state == GateState.PENDING],
                key=lambda e: e.priority_score,
                reverse=True,
            )

    def is_approved(self, alert_id: str) -> bool:
        entry = self._entries.get(alert_id)
        return entry is not None and entry.state == GateState.APPROVED

    def stats(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for e in self._entries.values():
            counts[e.state.value] = counts.get(e.state.value, 0) + 1
        return counts

    # ------------------------------------------------------------------
    # Auto-escalation sweep
    # ------------------------------------------------------------------

    def sweep_escalations(self) -> List[str]:
        """Check PENDING entries and auto-escalate those past timeout.

        Returns list of escalated alert_ids. Call this periodically
        (e.g. from a background task or the cleanup loop).
        """
        if self.config.escalation_timeout_seconds <= 0:
            return []

        now = time.time()
        escalated: List[str] = []

        with self._lock:
            for entry in self._entries.values():
                if entry.state != GateState.PENDING:
                    continue
                elapsed = now - entry.submitted_ts
                if elapsed >= self.config.escalation_timeout_seconds:
                    entry.state = GateState.ESCALATED
                    entry.resolved_ts = now
                    entry.escalation_target = self.config.default_escalation_target
                    entry.notes = (
                        f'Auto-escalated after {int(elapsed)}s '
                        f'(threshold: {self.config.escalation_timeout_seconds}s)'
                    )
                    escalated.append(entry.alert_id)

        if escalated:
            logger.info('Auto-escalated %d alerts: %s', len(escalated), escalated[:5])
            self._persist_state()

        return escalated


# Singleton for the application lifecycle
_GLOBAL_GATE: AnalystGate | None = None


def get_analyst_gate() -> AnalystGate:
    """Return (or create) the global AnalystGate singleton."""
    global _GLOBAL_GATE
    if _GLOBAL_GATE is None:
        _GLOBAL_GATE = AnalystGate()
    return _GLOBAL_GATE
