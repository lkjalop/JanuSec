"""Lightweight correlation engine for Email -> Identity -> DevOps -> Endpoint stitching.

Stores short-lived sessions on disk under data/sessions for simplicity. Intended
as an MVP to exercise rules and produce RuleMatch-like incident drafts.
"""
from __future__ import annotations
import json
import os
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import uuid
import logging

from src.schemas.email import NormalizedEmailEvent

LOGGER = logging.getLogger(__name__)
SESSIONS_DIR = os.environ.get('SESSION_PERSIST_DIR', 'data/sessions')
os.makedirs(SESSIONS_DIR, exist_ok=True)


def _session_path(session_id: str) -> str:
    return os.path.join(SESSIONS_DIR, f"session_{session_id}.json")


class CorrelationEngine:
    def __init__(self, ttl_hours: int = 72):
        self.ttl = timedelta(hours=ttl_hours)

    def _now(self) -> datetime:
        return datetime.utcnow()

    def create_session(self, email_event: NormalizedEmailEvent) -> str:
        sid = str(uuid.uuid4())
        data = {
            'id': sid,
            'created_at': self._now().isoformat(),
            'email': email_event.model_dump(),
            'identity_events': [],
            'devops_events': [],
            'endpoint_events': [],
        }
        with open(_session_path(sid), 'w', encoding='utf-8') as fh:
            json.dump(data, fh)
        LOGGER.debug('Correlation session created %s', sid)
        return sid

    def append_identity(self, session_id: str, identity_event: Dict[str, Any]) -> bool:
        try:
            p = _session_path(session_id)
            with open(p, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
            data.setdefault('identity_events', []).append(identity_event)
            with open(p, 'w', encoding='utf-8') as fh:
                json.dump(data, fh)
            return True
        except Exception:
            LOGGER.exception('append_identity failed')
            return False

    def append_devops(self, session_id: str, devops_event: Dict[str, Any]) -> bool:
        try:
            p = _session_path(session_id)
            with open(p, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
            data.setdefault('devops_events', []).append(devops_event)
            with open(p, 'w', encoding='utf-8') as fh:
                json.dump(data, fh)
            return True
        except Exception:
            LOGGER.exception('append_devops failed')
            return False

    def append_endpoint(self, session_id: str, endpoint_event: Dict[str, Any]) -> bool:
        try:
            p = _session_path(session_id)
            with open(p, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
            data.setdefault('endpoint_events', []).append(endpoint_event)
            with open(p, 'w', encoding='utf-8') as fh:
                json.dump(data, fh)
            return True
        except Exception:
            LOGGER.exception('append_endpoint failed')
            return False

    def evaluate_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        try:
            p = _session_path(session_id)
            with open(p, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
            created = datetime.fromisoformat(data.get('created_at'))
            if self._now() > created + self.ttl:
                LOGGER.debug('session %s expired', session_id)
                return None

            # Simple scoring: each stage present adds weight
            score = 0.0
            stages = []
            if data.get('email'):
                stages.append('email')
                score += 0.3
            if data.get('identity_events'):
                stages.append('identity')
                score += 0.3
            if data.get('devops_events'):
                stages.append('devops')
                score += 0.2
            if data.get('endpoint_events'):
                stages.append('endpoint')
                score += 0.2

            verdict = {
                'session_id': session_id,
                'stages': stages,
                'score': min(score, 1.0),
                'created_at': data.get('created_at'),
            }
            return verdict
        except Exception:
            LOGGER.exception('evaluate_session failed')
            return None


__all__ = ["CorrelationEngine"]
"""Simple correlation engine scaffold to accept normalized events and run chain evaluators."""
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

from src.schemas.email import NormalizedEmailEvent
from src.detection.supply_chain_rules import DeveloperTargetedPhishing, SupplyChainAttackChain


class CorrelationEngine:
    def __init__(self):
        self.dev_rule = DeveloperTargetedPhishing()
        self.chain_rule = SupplyChainAttackChain()
        # simple in-memory message store keyed by message_id for enrichment/testing
        self._message_store = {}

    def evaluate_email(self, event: NormalizedEmailEvent, store: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        matches = []
        m = self.dev_rule.evaluate(event)
        if m:
            matches.append({"rule": m.rule_id, "severity": m.severity, "confidence": m.confidence, "desc": m.description, "evidence": m.evidence})

        # attempt to correlate chain using simple store lookups
        identity_events = store.get("identity", [])
        devops_events = store.get("devops", [])
        endpoint_events = store.get("endpoint", [])

        # synchronous wrapper around async evaluate_chain (scaffold uses no await)
        import asyncio
        coro = self.chain_rule.evaluate_chain(event, identity_events, devops_events, endpoint_events)
        try:
            chain_match = asyncio.get_event_loop().run_until_complete(coro)
        except Exception:
            chain_match = None

        if chain_match:
            matches.append({"rule": chain_match.rule_id, "severity": chain_match.severity, "confidence": chain_match.confidence, "desc": chain_match.description, "evidence": chain_match.evidence})

        return matches

    def enrich_click(self, click_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich a click payload by attaching message context when available.

        Expects click_payload to contain `message_id` and `user`.
        """
        mid = click_payload.get("message_id")
        msg = self._message_store.get(mid)
        out = {"click": click_payload, "message": msg}
        # Optionally attach simple verdict: if message present and dev rule matches
        if msg:
            try:
                ne = NormalizedEmailEvent(**msg)
                m = self.dev_rule.evaluate(ne)
                out["dev_rule_match"] = bool(m)
                # Attach click context into message raw_event with mapping confidence
                raw = msg.setdefault("raw_event", {}) if isinstance(msg, dict) else {}
                lst = raw.setdefault("click_events", [])
                ctx = {
                    "user": click_payload.get("user"),
                    "ip": (click_payload.get("meta") or {}).get("ip") if isinstance(click_payload.get("meta"), dict) else click_payload.get("ip"),
                    "ua": (click_payload.get("meta") or {}).get("ua") if isinstance(click_payload.get("meta"), dict) else click_payload.get("user_agent"),
                    "url": click_payload.get("url"),
                    "verdict": click_payload.get("verdict"),
                    "mapping_confidence": 1.0,
                }
                lst.append(ctx)
            except Exception:
                out["dev_rule_match"] = False
        return out

    def index_message_for_enrichment(self, normalized_event: Dict[str, Any]):
        mid = normalized_event.get("message_id")
        if mid:
            self._message_store[mid] = normalized_event


__all__ = ["CorrelationEngine"]
