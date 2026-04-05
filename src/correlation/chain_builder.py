from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class ChainStage:
    domain: str  # email|identity|devops|endpoint
    event_id: str
    timestamp: float
    details: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0


@dataclass
class ChainRecord:
    chain_id: str
    root_email_id: Optional[str]
    created_ts: float
    updated_ts: float
    stages: List[ChainStage] = field(default_factory=list)
    confidence: float = 0.0
    recommended_actions: List[Dict[str, Any]] = field(default_factory=list)


class _InMemoryChains:
    def __init__(self, ttl_seconds: int = 72 * 3600):
        self.ttl = ttl_seconds
        self.store: Dict[str, ChainRecord] = {}

    def get(self, cid: str) -> Optional[ChainRecord]:
        rec = self.store.get(cid)
        if not rec:
            return None
        if time.time() - rec.updated_ts > self.ttl:
            self.store.pop(cid, None)
            return None
        return rec

    def put(self, rec: ChainRecord) -> None:
        self.store[rec.chain_id] = rec


class ChainBuilder:
    def __init__(self, ttl_seconds: int = 72 * 3600):
        self.db = _InMemoryChains(ttl_seconds=ttl_seconds)

    def _cid(self, email_event_id: str) -> str:
        return f"chain-{email_event_id}"

    def build_or_update(self,
                        email_event: Optional[Any] = None,
                        identity_events: Optional[List[Dict[str, Any]]] = None,
                        devops_events: Optional[List[Dict[str, Any]]] = None,
                        endpoint_events: Optional[List[Dict[str, Any]]] = None,
                        window_seconds: int = 72 * 3600) -> ChainRecord:
        root_id = getattr(email_event, "event_id", None)
        cid = self._cid(root_id or f"{int(time.time()*1000)}")
        now = time.time()
        rec = self.db.get(cid) or ChainRecord(chain_id=cid, root_email_id=root_id, created_ts=now, updated_ts=now)

        def _add(domain: str, ev: Dict[str, Any], base_conf: float) -> None:
            ts = ev.get("timestamp") or now
            if root_id and abs(ts - (getattr(email_event, "timestamp", ts))) > window_seconds:
                return
            stage = ChainStage(domain=domain, event_id=str(ev.get("event_id") or ev.get("id") or f"{domain}-{int(ts)}"),
                               timestamp=ts, details=ev, confidence=base_conf)
            rec.stages.append(stage)

        if email_event:
            _add("email", {"event_id": email_event.event_id, "timestamp": getattr(email_event, "timestamp", now),
                           "subject": getattr(email_event, "subject", ""), "sender": getattr(email_event, "sender", {})}, base_conf=0.4)

        for ev in identity_events or []:
            _add("identity", ev, base_conf=0.3)
        for ev in devops_events or []:
            _add("devops", ev, base_conf=0.3)
        for ev in endpoint_events or []:
            _add("endpoint", ev, base_conf=0.4)

        # Aggregate confidence (simple additive capped)
        rec.confidence = min(sum(s.confidence for s in rec.stages), 1.0)

        # Recommended actions heuristic
        rec.recommended_actions = []
        has_identity = any(s.domain == "identity" for s in rec.stages)
        has_devops = any(s.domain == "devops" for s in rec.stages)
        has_endpoint = any(s.domain == "endpoint" for s in rec.stages)
        if has_identity:
            rec.recommended_actions.append({"id": "revoke_oauth", "domain": "identity", "priority": "high"})
        if has_devops:
            rec.recommended_actions.append({"id": "quarantine_similar", "domain": "email", "priority": "high"})
        if has_endpoint:
            rec.recommended_actions.append({"id": "isolate_host", "domain": "endpoint", "priority": "high"})

        rec.updated_ts = now
        self.db.put(rec)
        return rec


__all__ = ["ChainBuilder", "ChainRecord", "ChainStage"]
