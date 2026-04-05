"""Supply-chain incident playbook templates and helper runner.

This module provides structured playbook steps that can be executed by
an orchestration layer or presented to analysts in the UI.
"""
from __future__ import annotations
from typing import List, Dict, Any


PLAYBOOK = [
    {"id": "identify_scope", "title": "Identify Scope", "steps": [
        "List affected packages and repos",
        "List affected developers and tokens",
        "Collect timeframe and telemetry"
    ]},
    {"id": "containment", "title": "Containment", "steps": [
        "Quarantine messages matching IOCs/cluster",
        "Revoke exposed OAuth tokens (after approval)",
        "Block malicious domains at gateway"
    ]},
    {"id": "eradication", "title": "Eradication & Recovery", "steps": [
        "Remove poisoned packages and revoke releases",
        "Rotate keys/secrets used by CI/CD",
        "Patch build hosts and redeploy clean artifacts"
    ]},
    {"id": "postmortem", "title": "Postmortem & Notification", "steps": [
        "Prepare customer notification template",
        "File reports with registry maintainers (npm/pypi)",
        "Update detection signatures and test harness"
    ]}
]


def get_playbook() -> List[Dict[str, Any]]:
    return PLAYBOOK


__all__ = ["get_playbook"]
from __future__ import annotations
from typing import List, Dict, Any
from datetime import datetime


class PlaybookStep:
    def __init__(self, id: str, title: str, description: str, action: str):
        self.id = id
        self.title = title
        self.description = description
        self.action = action
        self.created_at = datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "action": self.action,
            "created_at": self.created_at.isoformat(),
        }


class SupplyChainPlaybook:
    def __init__(self):
        self.steps: List[PlaybookStep] = []
        # default steps (non-destructive first)
        self.steps.append(PlaybookStep("1", "Contain and Triage", "Quarantine affected messages and collect IOCs", "quarantine_messages"))
        self.steps.append(PlaybookStep("2", "Revoke Tokens", "Revoke suspected OAuth tokens for impacted accounts", "revoke_tokens"))
        self.steps.append(PlaybookStep("3", "Audit Repos", "Scan recent commits and package publishes for malicious code", "audit_repos"))
        self.steps.append(PlaybookStep("4", "Endpoint Scan", "Run AV/EPP scan on developer endpoints", "endpoint_scan"))

    def get_steps(self) -> List[Dict[str, Any]]:
        return [s.to_dict() for s in self.steps]


class Notifier:
    @staticmethod
    def notify_operators(subject: str, body: str, channels: List[str] = None) -> None:
        # Stub: wire into Slack/Teams/Email in production
        print(f"ALERT: {subject}\n{body}")
