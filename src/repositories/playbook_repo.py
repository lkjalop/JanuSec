import json
from typing import Dict, Any, List

PLAYBOOK_PATH = 'data/playbooks.json'

DEFAULT_PLAYBOOKS = {
    "malware": {"actions": ["isolate", "block", "create_ticket", "export_intel"], "priority": "high"},
    "phishing": {"actions": ["block", "create_ticket", "export_intel"], "priority": "medium"},
    "suspicious": {"actions": ["create_ticket", "export_intel"], "priority": "low"}
}


def load_playbooks() -> Dict[str, Any]:
    try:
        with open(PLAYBOOK_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)
            # normalize list -> dict by id/title when older format used
            if isinstance(data, list):
                out = {}
                for e in data:
                    key = (e.get('id') or e.get('title') or '').lower()
                    if not key:
                        continue
                    out[key] = e
                return out
            if isinstance(data, dict):
                return data
            return DEFAULT_PLAYBOOKS.copy()
    except Exception:
        return DEFAULT_PLAYBOOKS.copy()


def save_playbooks(playbooks: Dict[str, Any]) -> None:
    with open(PLAYBOOK_PATH, 'w', encoding='utf-8') as f:
        json.dump(playbooks, f, indent=2)


def get_playbook_for_verdict(verdict: str) -> Dict[str, Any]:
    playbooks = load_playbooks()
    if not verdict:
        return playbooks.get('suspicious', {})
    v = str(verdict).lower()
    # direct match
    if v in playbooks:
        return playbooks[v]
    # try partial match by keywords
    for k, val in playbooks.items():
        if v in k:
            return val
    return playbooks.get('suspicious', {})
