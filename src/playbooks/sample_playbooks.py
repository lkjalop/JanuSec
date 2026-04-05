from __future__ import annotations
from typing import Dict, Any

from src.core.storage.report_store import report_store


def generate_ransomware_playbook(report_id: str) -> Dict[str, Any]:
    report = report_store.get(report_id) or {}
    suggested_actions = []
    if report.get('mitre'):
        for t in report.get('mitre'):
            name = (t.get('name') or '').lower()
            if 'ransom' in name or 'data encrypted' in name:
                suggested_actions.extend([
                    {'action': 'isolate_hosts', 'details': 'Disconnect affected hosts from network'},
                    {'action': 'snapshot', 'details': 'Create forensic snapshots'},
                    {'action': 'collect_edr', 'details': 'Collect EDR logs for affected hosts'},
                ])
                break
    # fallback generic actions
    if not suggested_actions:
        suggested_actions = [
            {'action': 'investigate', 'details': 'Collect telemetry and escalate'},
        ]
    return {'playbook_id': f'pb-ransom-{report_id}', 'actions': suggested_actions, 'evidence': report.get('evidence', [])}


def generate_bec_playbook(report_id: str) -> Dict[str, Any]:
    report = report_store.get(report_id) or {}
    actions = [
        {'action': 'block_sender', 'details': 'Block sender at mail gateway'},
        {'action': 'quarantine_message', 'details': 'Quarantine suspicious messages'},
        {'action': 'notify_users', 'details': 'Send template notification to recipients'},
    ]
    return {'playbook_id': f'pb-bec-{report_id}', 'actions': actions, 'evidence': report.get('evidence', [])}
