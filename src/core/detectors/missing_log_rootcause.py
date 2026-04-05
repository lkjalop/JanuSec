from __future__ import annotations

from typing import Any, Dict, List
from src.core.playbooks import execute_playbook
from src.core.rca import analyze_root_causes


def diagnose_and_suggest_actions(tenant: str, expected_sources: List[str]) -> List[Dict[str, Any]]:
    """Run RCA and return suggested safe remediation previews for missing log sources.

    Returns list of {source, anomaly, top_hypothesis, confidence, suggested_action, remediation_preview}
    """
    rc = analyze_root_causes(tenant, expected_sources)
    suggestions: List[Dict[str, Any]] = []
    for r in rc:
        src = r.get('source')
        top = r.get('top_hypothesis')
        conf = r.get('confidence')
        # map top hypothesis to safe playbook
        if top == 'collector_failure':
            preview = execute_playbook('restart_collector', target=src, dry_run=True)
            action = 'restart_collector'
        elif top == 'authentication_issue':
            preview = execute_playbook('refresh_api_token', target=src, dry_run=True)
            action = 'refresh_api_token'
        elif top == 'rate_limiting':
            preview = {'action': 'rate_limit_advice', 'status': 'preview', 'details': 'increase API quota or backoff'}
            action = 'rate_limiting'
        else:
            preview = {'action': 'investigate', 'status': 'preview'}
            action = 'investigate'

        suggestions.append({
            'source': src,
            'anomaly': r.get('anomaly'),
            'top_hypothesis': top,
            'confidence': conf,
            'suggested_action': action,
            'remediation_preview': preview,
            'evidence': r.get('evidence'),
        })

    return suggestions


__all__ = ['diagnose_and_suggest_actions']
