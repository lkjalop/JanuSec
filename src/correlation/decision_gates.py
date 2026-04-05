from __future__ import annotations
import os
import json
import time
from typing import Any, Dict

AUDIT_DIR = os.path.join("data", "audit")
os.makedirs(AUDIT_DIR, exist_ok=True)
AUDIT_PATH = os.path.join(AUDIT_DIR, "decision_gates.json")


class GateManager:
    """Simple decision gate manager with audit logging.

    Records approvals/denials and optional notes to a JSON log.
    """

    def __init__(self, path: str = AUDIT_PATH):
        self.path = path
        if not os.path.exists(self.path):
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump({"entries": []}, f)

    def record(self, action: str, status: str, actor: str, context: Dict[str, Any] | None = None) -> None:
        entry = {
            "ts": time.time(),
            "action": action,
            "status": status,
            "actor": actor,
            "context": context or {},
        }
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {"entries": []}
        data.setdefault("entries", []).append(entry)
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass


__all__ = ["GateManager"]"""Decision gate manager for safe automated remediation with audit logging."""
from __future__ import annotations
from typing import Dict, Any, Optional
from datetime import datetime
import json
import os
import logging

LOG_PATH = os.environ.get('DECISION_AUDIT_LOG', 'data/decision_audit.log')
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True) if os.path.dirname(LOG_PATH) else None

LOGGER = logging.getLogger(__name__)


def audit_action(action: str, details: Dict[str, Any], actor: Optional[str] = None) -> None:
    rec = {
        'ts': datetime.utcnow().isoformat(),
        'action': action,
        'actor': actor or 'system',
        'details': details,
    }
    try:
        with open(LOG_PATH, 'a', encoding='utf-8') as fh:
            fh.write(json.dumps(rec) + '\n')
    except Exception:
        LOGGER.exception('Failed to write decision audit')


def evaluate_decision_gate(session_summary: Dict[str, Any], policy_overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Simple gate evaluator that returns recommended actions and whether auto-action is allowed.

    For production, replace with policy engine and RBAC/approval flows.
    """
    score = session_summary.get('score', 0.0)
    stages = session_summary.get('stages', [])

    if score >= 0.9 and 'endpoint' in stages:
        recommended = ['revoke_oauth_tokens', 'quarantine_messages', 'full_ir']
        auto_allowed = False  # destructive actions require human approval
    elif score >= 0.6:
        recommended = ['quarantine_messages', 'notify_admins']
        auto_allowed = True
    else:
        recommended = ['monitor', 'notify_admins']
        auto_allowed = True

    return {'recommended': recommended, 'auto_allowed': auto_allowed, 'score': score}


__all__ = ["audit_action", "evaluate_decision_gate"]
