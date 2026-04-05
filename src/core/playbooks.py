from __future__ import annotations
from typing import Dict, Any, List, Optional
import os
import logging

LOG = logging.getLogger(__name__)


def execute_playbook(action: str, target: str, params: Dict[str, Any] | None = None, dry_run: bool = True, require_approval: bool = False) -> Dict[str, Any]:
    """Execute a simple pre-defined playbook action safely.

    - `dry_run=True` avoids side-effects and returns a preview.
    - `require_approval=True` returns an approval token instead of executing.
    """
    if require_approval:
        token = f"approval-{action}-{target}"
        LOG.info("Playbook requires approval: %s target=%s", action, target)
        return {"action": action, "target": target, "status": "requires_approval", "approval_token": token}

    if dry_run or os.environ.get('ENABLE_AUTO_REMEDIATION','0').lower() not in {'1','true','yes'}:
        LOG.info("dry_run playbook %s target=%s", action, target)
        return {"action": action, "target": target, "status": "dry_run", "params": params}

    # Implement a few safe actions (bridge to src.core.remediation)
    try:
        if action == 'restart_collector':
            from src.core.remediation import restart_collector
            return restart_collector(target, dry_run=False)
        if action == 'refresh_api_token':
            from src.core.remediation import refresh_api_token
            return refresh_api_token(target, dry_run=False)
        # unknown action
        return {"action": action, "target": target, "status": "error", "details": "unknown action"}
    except Exception as e:
        LOG.exception("playbook execution failed")
        return {"action": action, "target": target, "status": "error", "details": str(e)}


__all__ = ["execute_playbook"]
