from __future__ import annotations
from typing import Dict, List


def developer_targeted_phishing_playbook(recipient: str | None = None) -> Dict[str, List[str]]:
    steps = [
        "Block sender domain and quarantine similar messages",
        f"Alert {recipient or 'developer'} to avoid clicking or authorizing apps",
        "Review recent OAuth grants for the user",
        "Audit repository access and recent package publishes",
        "Check CI/CD pipeline modifications and secret access",
        "Scan developer endpoints for malware",
    ]
    return {
        "summary": "Playbook for developer-targeted phishing (supply chain risk)",
        "steps": steps,
    }


__all__ = ["developer_targeted_phishing_playbook"]