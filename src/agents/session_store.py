"""
Investigation session persistence facade.

Keeps the agent loop decoupled from storage implementation details.
Each investigation run creates one InvestigationSessionStore that writes
every completed cycle to DuckDB so the investigation can survive restarts
and be resumed or audited later.
"""
from __future__ import annotations

import dataclasses
import json
import logging
import time
from typing import Any

LOGGER = logging.getLogger(__name__)


def _serialise(obj: Any) -> Any:
    """Recursively convert dataclasses and standard types to JSON-safe values."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _serialise(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, (list, tuple)):
        return [_serialise(i) for i in obj]
    if isinstance(obj, dict):
        return {k: _serialise(v) for k, v in obj.items()}
    if isinstance(obj, float) and obj != obj:  # NaN guard
        return None
    return obj


class InvestigationSessionStore:
    """Manages persistence for one investigation session."""

    def __init__(
        self,
        session_id: str,
        tenant_id: str,
        assessment_id: str,
        cluster_id: str = "",
    ) -> None:
        self.session_id = session_id
        self.tenant_id = tenant_id
        self.assessment_id = assessment_id
        self.cluster_id = cluster_id
        self._available = self._create()

    def _create(self) -> bool:
        try:
            from src.core.ingest.store import create_investigation_session
            create_investigation_session(
                self.session_id, self.tenant_id,
                self.assessment_id, self.cluster_id,
            )
            return True
        except Exception as exc:
            LOGGER.warning("session store unavailable — investigation will not persist: %s", exc)
            return False

    def append_cycle(self, cycle_summary: dict, resumable_state: dict) -> None:
        """Append a completed cycle event and update the resumable snapshot."""
        if not self._available:
            return
        try:
            from src.core.ingest.store import (
                append_investigation_event,
                update_investigation_state,
            )
            event = {
                "type": "cycle_complete",
                "ts": time.time(),
                "cycle": cycle_summary.get("cycle"),
                "findings_verified": cycle_summary.get("findings_verified", 0),
                "findings_rejected": cycle_summary.get("findings_rejected", 0),
                "findings_weak": cycle_summary.get("findings_weak", 0),
                "hypothesis": cycle_summary.get("hypothesis", ""),
            }
            append_investigation_event(self.session_id, event)
            update_investigation_state(
                self.session_id,
                state=_serialise(resumable_state),
            )
        except Exception as exc:
            LOGGER.warning("failed to persist cycle to session store: %s", exc)

    def close(self, close_reason: str, final_state: dict) -> None:
        if not self._available:
            return
        try:
            from src.core.ingest.store import update_investigation_state
            update_investigation_state(
                self.session_id,
                state=_serialise(final_state),
                status="complete",
                close_reason=close_reason,
            )
        except Exception as exc:
            LOGGER.warning("failed to close session in store: %s", exc)

    @staticmethod
    def load(session_id: str) -> dict | None:
        """Load a session's full record including resumable state. Returns None if missing."""
        try:
            from src.core.ingest.store import get_investigation_session
            return get_investigation_session(session_id)
        except Exception as exc:
            LOGGER.warning("failed to load session %s: %s", session_id, exc)
            return None
