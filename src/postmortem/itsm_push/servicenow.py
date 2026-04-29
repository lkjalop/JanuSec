"""
ServiceNow Push — v2 STUB
=========================

v1 status: STUB — returns a payload preview but does not call the API.

In v2 this module will use ServiceNow's Table API to create:
  - 1 ``incident`` record (parent)
  - N ``incident_task`` records (children, linked via parent_incident_sys_id)

The shape of the payload is defined in
``data_shapes/itsm_servicenow_schema.json``. The v2 implementation will
mirror jira.py's structure with these adjustments:

  - Auth: OAuth 2.0 (not basic_auth or bearer)
  - URL pattern: /api/now/table/incident, /api/now/table/incident_task
  - Custom fields: u_janusec_* prefix (not customfield_*)
  - Description format: plain text (not ADF)
  - Linkage: parent_incident_sys_id (not parent.key)

WHY V2 NOT V1
-------------
ServiceNow OAuth setup is more involved than Atlassian basic_auth and the
AU SMB / mid-market customer base trends toward Atlassian. Once a
ServiceNow customer is signed, this module gets fully implemented.
"""
from __future__ import annotations


def push(
    *,
    document: dict,
    config: dict,
    dry_run: bool = False,
) -> dict:
    """v2 stub. Returns a payload preview without making API calls."""
    payload = _build_preview_payload(document, config)
    return {
        "success": False,
        "error":   "servicenow_integration_v2_only",
        "v1_note": "ServiceNow push is implemented in v2. Use Jira (target='jira') "
                   "or Confluence (target='confluence') in v1.",
        "preview_payload": payload,
    }


def _build_preview_payload(document: dict, config: dict) -> dict:
    cluster_id = document.get("cluster_id", "?")
    pm_id = document.get("postmortem_id", "?")
    verdict = (document.get("verdict") or {}).get("platform_verdict", "?")

    # Reads sections via computed view so previews include human edits.
    from src.postmortem.postmortem_assembler import get_computed_section
    s7 = get_computed_section(document, "s7_corrective_actions")
    s6 = get_computed_section(document, "s6_regulatory_clocks")

    preview = {
        "incident": {
            "short_description": f"JanuSec Postmortem: {cluster_id} — {verdict}",
            "description":       f"Postmortem ID: {pm_id}",
            "category":          "security_incident",
            "subcategory":       "data_breach",
            "impact":            "1",
            "urgency":           "1",
            "u_janusec_postmortem_id": pm_id,
            "u_janusec_cluster_id":    cluster_id,
            "u_janusec_verdict":       verdict,
        },
        "child_tasks": [],
    }
    for action in (s7.get("actions") or []):
        preview["child_tasks"].append({
            "short_description": f"[CORRECTIVE] {action.get('title','')[:240]}",
            "u_janusec_section": "s7",
            "u_janusec_action_id": action.get("action_id"),
        })
    for trigger in (s6.get("triggers") or []):
        preview["child_tasks"].append({
            "short_description": f"[REGULATORY] {trigger.get('regulator','?')} "
                                 f"— {trigger.get('clock_human','?')} clock",
            "u_janusec_section": "s6",
            "u_janusec_regulator": trigger.get("trigger_id"),
        })
    return preview


__all__ = ["push"]
