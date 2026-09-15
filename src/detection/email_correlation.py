from __future__ import annotations
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import uuid

from src.schemas.email import NormalizedEmailEvent


class CorrelationStore:
    """In-memory correlation store for MVP. Replace with persistent store in prod."""
    def __init__(self):
        self.sessions: Dict[str, Dict[str, Any]] = {}

    def create_session(self, root_event: NormalizedEmailEvent) -> str:
        sid = f"chain-{uuid.uuid4().hex[:8]}"
        self.sessions[sid] = {
            "id": sid,
            "root_event": root_event,
            "identity": [],
            "devops": [],
            "endpoint": [],
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }
        return sid

    def add_identity_event(self, session_id: str, ev: Dict[str, Any]):
        s = self.sessions.get(session_id)
        if not s:
            return False
        s["identity"].append(ev)
        s["updated_at"] = datetime.utcnow()
        return True

    def add_devops_event(self, session_id: str, ev: Dict[str, Any]):
        s = self.sessions.get(session_id)
        if not s:
            return False
        s["devops"].append(ev)
        s["updated_at"] = datetime.utcnow()
        return True

    def add_endpoint_event(self, session_id: str, ev: Dict[str, Any]):
        s = self.sessions.get(session_id)
        if not s:
            return False
        s["endpoint"].append(ev)
        s["updated_at"] = datetime.utcnow()
        return True

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        return self.sessions.get(session_id)

    def prune_expired(self, ttl_hours: int = 72):
        now = datetime.utcnow()
        remove = []
        for sid, s in self.sessions.items():
            if s["updated_at"] + timedelta(hours=ttl_hours) < now:
                remove.append(sid)
        for sid in remove:
            del self.sessions[sid]


class CorrelationEngine:
    def __init__(self, store: CorrelationStore):
        self.store = store

    def start_chain(self, email_event: NormalizedEmailEvent) -> str:
        sid = self.store.create_session(email_event)
        return sid

    def score_chain(self, session_id: str) -> float:
        s = self.store.get_session(session_id)
        if not s:
            return 0.0
        score = 0.0
        # simple scoring: +0.7 for identity events, +0.8 for devops, +0.9 for endpoint
        score += min(1.0, 0.7 * len(s.get("identity", [])))
        score += min(1.0, 0.8 * len(s.get("devops", [])))
        score += min(1.0, 0.9 * len(s.get("endpoint", [])))
        # normalize
        return min(1.0, score / 3.0)
