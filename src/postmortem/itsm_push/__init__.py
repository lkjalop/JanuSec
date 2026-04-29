"""ITSM push — pushes assembled postmortem to customer's existing ITSM.

v1: Jira (primary), Confluence (secondary), ServiceNow (stub for v2).

Usage:
    from src.postmortem.itsm_push import push_postmortem

    result = push_postmortem(
        document=postmortem_document,
        target='jira',
        config={...},  # from _STATE['jira'] in integrations_endpoints.py
    )
    # returns {'success': True, 'parent_key': 'SEC-1234', 'child_keys': [...]}
"""
from __future__ import annotations

from typing import Any

from . import jira as _jira
from . import confluence as _confluence
from . import servicenow as _servicenow


def push_postmortem(
    *,
    document: dict,
    target: str,
    config: dict,
    dry_run: bool = False,
) -> dict:
    """Dispatch to the correct ITSM module.

    target: 'jira' | 'confluence' | 'servicenow'
    config: target-specific config dict (auth, project_key, etc.)
    dry_run: if True, builds the payload but does not actually call the API.
             Returns the payload for review. Used by the UI's "Preview push"
             button to show the analyst exactly what would be sent.
    """
    target = (target or "").lower()
    if target == "jira":
        return _jira.push(document=document, config=config, dry_run=dry_run)
    if target == "confluence":
        return _confluence.push(document=document, config=config, dry_run=dry_run)
    if target == "servicenow":
        return _servicenow.push(document=document, config=config, dry_run=dry_run)
    return {"success": False, "error": f"unknown target: {target}"}


__all__ = ["push_postmortem"]
