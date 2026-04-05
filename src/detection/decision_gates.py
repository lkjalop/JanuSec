from __future__ import annotations
from typing import Dict, Any, Optional
from datetime import datetime


class DecisionGate:
    def __init__(self, question: str, options: list, urgency: str = "normal"):
        self.question = question
        self.options = options
        self.urgency = urgency
        self.created_at = datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "question": self.question,
            "options": self.options,
            "urgency": self.urgency,
            "created_at": self.created_at.isoformat(),
        }


class DecisionAudit:
    _audit: list[Dict[str, Any]] = []

    @classmethod
    def record(cls, gate: DecisionGate, actor: str, choice: str, comment: Optional[str] = None):
        entry = {
            "gate": gate.to_dict(),
            "actor": actor,
            "choice": choice,
            "comment": comment,
            "ts": datetime.utcnow().isoformat(),
        }
        cls._audit.append(entry)
        return entry
