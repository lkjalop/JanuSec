"""
Jira ITSM Push — v1 Primary Integration
=======================================

Creates parent Incident issue + child Tasks in the customer's Jira project
from an assembled PostmortemDocument.

WHY JIRA FIRST
--------------
1. AU SMB and mid-market use Jira way more than ServiceNow.
2. ``integrations_endpoints.py:_STATE['jira']`` already has ``webhook_url``
   and ``connected`` plumbing — we extend rather than green-field.
3. Jira's REST v3 API + Atlassian Document Format (ADF) descriptions are
   well-documented and stable.

AUTH MODEL
----------
v1 supports two auth models — the customer picks at integration setup time:
  - ``basic_auth`` with email + API token (recommended; works for Atlassian Cloud)
  - ``bearer_token`` for self-hosted Jira Server with PAT

Auth credentials are read from config dict; not hardcoded. The config dict
should match the shape of ``_STATE['jira']`` in integrations_endpoints.py
extended with ``auth`` block:

    {
        "connected": true,
        "base_url": "https://acme.atlassian.net",
        "project_key": "SEC",
        "parent_issue_type_name": "Incident",
        "child_issue_type_name": "Task",
        "auth": {
            "method": "basic_auth",
            "email": "janusec-bot@acme.com",
            "api_token": "<from env or vault>"
        },
        "custom_fields": {
            "postmortem_id":      "customfield_10100",
            "verdict":            "customfield_10101",
            "section":            "customfield_10102",
            "regulator":          "customfield_10103",
            "clock_deadline":     "customfield_10104"
        }
    }

If ``custom_fields`` is missing, falls back to labels — every postmortem
gets ``janusec``, ``postmortem``, and section/regulator-specific labels.

WHAT GETS PUSHED
----------------
  Parent issue: 1 per postmortem
    title:       "JanuSec Postmortem: cluster_X — VERDICT"
    description: Section 1 narrative + verdict block (ADF formatted)
    labels:      janusec, postmortem, security-incident, <verdict>

  Child tasks: 1 per s7 corrective action + 1 per s6 regulatory trigger + 1 per s5 risk candidate
    Linked to parent via ``parent`` field (Jira sub-task pattern).

DRY RUN
-------
``dry_run=True`` returns the payload that would be sent without making any
HTTP calls. Used by the "Preview push to Jira" UI button so the analyst
can see exactly what will land in Jira before confirming.

ERROR HANDLING
--------------
Any single child task failure does NOT abort the whole push — the parent
issue is created, child tasks are attempted independently, and the result
records which succeeded and which failed.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Lazy import of requests so this module imports cleanly in environments
# where the Jira integration isn't being used.
try:
    import requests
except ImportError:
    requests = None


def push(
    *,
    document: dict,
    config: dict,
    dry_run: bool = False,
) -> dict:
    """Build and push a PostmortemDocument to Jira."""
    base_url = config.get("base_url", "").rstrip("/")
    project_key = config.get("project_key", "")
    if not base_url or not project_key:
        return {
            "success": False,
            "error": "jira config missing base_url or project_key",
        }

    parent_payload = _build_parent_payload(document, config)
    child_payloads = _build_child_payloads(document, config)

    if dry_run:
        return {
            "success": True,
            "dry_run": True,
            "parent_payload": parent_payload,
            "child_payloads": child_payloads,
            "would_call": {
                "parent_url": f"{base_url}/rest/api/3/issue",
                "child_url":  f"{base_url}/rest/api/3/issue",
                "child_count": len(child_payloads),
            },
        }

    if requests is None:
        return {"success": False, "error": "requests library not available"}

    auth = _build_auth_handle(config.get("auth") or {})
    if auth is None:
        return {"success": False, "error": "jira auth not configured"}

    # Create parent issue.
    parent_resp = _create_issue(base_url, parent_payload, auth)
    if not parent_resp.get("success"):
        return {
            "success": False,
            "error": "parent_issue_creation_failed",
            "details": parent_resp,
        }
    parent_key = parent_resp.get("issue_key")
    parent_id = parent_resp.get("issue_id")

    # Create child tasks linked to parent.
    child_results: list[dict] = []
    for child_payload in child_payloads:
        # Add parent linkage now that we have the parent key.
        child_payload["fields"]["parent"] = {"key": parent_key}
        child_resp = _create_issue(base_url, child_payload, auth)
        child_results.append({
            "task_type":   child_payload.get("_task_type"),
            "summary":     child_payload["fields"].get("summary"),
            "success":     child_resp.get("success"),
            "issue_key":   child_resp.get("issue_key"),
            "error":       child_resp.get("error"),
        })

    return {
        "success":      True,
        "parent_key":   parent_key,
        "parent_id":    parent_id,
        "parent_url":   f"{base_url}/browse/{parent_key}",
        "child_count":  len(child_results),
        "children":     child_results,
        "any_failed":   any(not c["success"] for c in child_results),
    }


# ─────────────────────────────────────────────────────────────────────────────
#  Payload construction
# ─────────────────────────────────────────────────────────────────────────────


def _build_parent_payload(document: dict, config: dict) -> dict:
    project_key = config["project_key"]
    issue_type = config.get("parent_issue_type_name", "Incident")
    custom_fields = config.get("custom_fields") or {}

    cluster_id = document.get("cluster_id", "?")
    verdict = (document.get("verdict") or {}).get("platform_verdict", "UNKNOWN")
    confidence = (document.get("verdict") or {}).get("confidence", 0.0)
    pm_id = document.get("postmortem_id", "?")
    pm_url = config.get("base_janusec_url", "") + f"/postmortem/{pm_id}"

    # Build description from Section 1 narrative, verdict, and section list.
    description_adf = _build_parent_description_adf(document)

    fields: dict[str, Any] = {
        "project":     {"key": project_key},
        "issuetype":   {"name": issue_type},
        "summary":     f"JanuSec Postmortem: {cluster_id} — {verdict}",
        "description": description_adf,
        "priority":    _verdict_to_jira_priority(verdict),
        "labels":      _build_labels(document, scope="parent"),
    }

    # Apply custom field mappings if configured.
    if custom_fields.get("postmortem_id"):
        fields[custom_fields["postmortem_id"]] = pm_id
    if custom_fields.get("verdict"):
        fields[custom_fields["verdict"]] = verdict
    if custom_fields.get("janusec_url"):
        fields[custom_fields["janusec_url"]] = pm_url

    return {"fields": fields, "_task_type": "parent_incident"}


def _build_child_payloads(document: dict, config: dict) -> list[dict]:
    project_key = config["project_key"]
    child_issue_type = config.get("child_issue_type_name", "Task")
    custom_fields = config.get("custom_fields") or {}
    children: list[dict] = []

    # Read sections via computed view (auto + overrides applied).
    from src.postmortem.postmortem_assembler import get_computed_section

    # ── Corrective action child tasks (from s7) ──────────────────────────────
    s7 = get_computed_section(document, "s7_corrective_actions")
    for action in (s7.get("actions") or []):
        children.append(_build_corrective_action_child(
            action, document, project_key, child_issue_type, custom_fields))

    # ── Regulatory notification child tasks (from s6) ────────────────────────
    s6 = get_computed_section(document, "s6_regulatory_clocks")
    for trigger in (s6.get("triggers") or []):
        children.append(_build_regulatory_child(
            trigger, document, project_key, child_issue_type, custom_fields))

    # ── Risk register review child tasks (from s5) ───────────────────────────
    s5 = get_computed_section(document, "s5_risk_register_delta")
    for candidate in (s5.get("new_risk_candidates") or []):
        children.append(_build_risk_review_child(
            candidate, document, project_key, child_issue_type, custom_fields))

    return children


def _build_corrective_action_child(
    action: dict, document: dict, project_key: str,
    issue_type: str, custom_fields: dict,
) -> dict:
    fields: dict[str, Any] = {
        "project":     {"key": project_key},
        "issuetype":   {"name": issue_type},
        "summary":     f"[CORRECTIVE] {action.get('title', 'Untitled action')[:240]}",
        "description": _action_description_adf(action, document),
        "priority":    _priority_to_jira(action.get("priority", "P3")),
        "labels":      _build_labels(document, scope="s7", extra=[action.get("priority", "P3").lower()]),
        "duedate":     _due_date_iso(action.get("due_days")),
    }
    if custom_fields.get("section"):
        fields[custom_fields["section"]] = "s7_corrective_actions"
    if custom_fields.get("postmortem_id"):
        fields[custom_fields["postmortem_id"]] = document.get("postmortem_id")
    return {
        "fields": fields,
        "_task_type": "corrective_action",
        "_action_id": action.get("action_id"),
    }


def _build_regulatory_child(
    trigger: dict, document: dict, project_key: str,
    issue_type: str, custom_fields: dict,
) -> dict:
    deadline = trigger.get("deadline")
    deadline_human = trigger.get("clock_human") or "??"
    regulator = trigger.get("regulator", "?")
    fields: dict[str, Any] = {
        "project":     {"key": project_key},
        "issuetype":   {"name": issue_type},
        "summary":     f"[REGULATORY] {regulator} notification — {deadline_human} clock",
        "description": _regulatory_description_adf(trigger, document),
        "priority":    {"name": "Highest"} if deadline_human in ("12h", "24h", "72h") else {"name": "High"},
        "labels":      _build_labels(document, scope="s6", extra=[
                          (trigger.get("trigger_id") or "").lower(),
                          (trigger.get("regulator") or "").lower(),
                          "regulatory",
                       ]),
        "duedate":     _deadline_iso_to_due_date(deadline, hours_buffer=24),
    }
    if custom_fields.get("section"):
        fields[custom_fields["section"]] = "s6_regulatory_clocks"
    if custom_fields.get("regulator"):
        fields[custom_fields["regulator"]] = trigger.get("trigger_id")
    if custom_fields.get("clock_deadline") and deadline:
        fields[custom_fields["clock_deadline"]] = deadline
    if custom_fields.get("postmortem_id"):
        fields[custom_fields["postmortem_id"]] = document.get("postmortem_id")
    return {
        "fields": fields,
        "_task_type": "regulatory_notification",
        "_trigger_id": trigger.get("trigger_id"),
    }


def _build_risk_review_child(
    candidate: dict, document: dict, project_key: str,
    issue_type: str, custom_fields: dict,
) -> dict:
    fields: dict[str, Any] = {
        "project":     {"key": project_key},
        "issuetype":   {"name": issue_type},
        "summary":     f"[RISK REVIEW] {candidate.get('title', '?')[:240]}",
        "description": _risk_description_adf(candidate, document),
        "priority":    {"name": "Medium"},
        "labels":      _build_labels(document, scope="s5", extra=["risk-register"]),
        "duedate":     _due_date_iso(14),
    }
    if custom_fields.get("section"):
        fields[custom_fields["section"]] = "s5_risk_register_delta"
    if custom_fields.get("postmortem_id"):
        fields[custom_fields["postmortem_id"]] = document.get("postmortem_id")
    return {
        "fields": fields,
        "_task_type": "risk_register_review",
        "_candidate_id": candidate.get("candidate_risk_id"),
    }


# ─────────────────────────────────────────────────────────────────────────────
#  ADF helpers (Atlassian Document Format)
# ─────────────────────────────────────────────────────────────────────────────


def _adf_paragraph(text: str) -> dict:
    return {
        "type": "paragraph",
        "content": [{"type": "text", "text": text or ""}],
    }


def _adf_heading(text: str, level: int = 2) -> dict:
    return {
        "type": "heading",
        "attrs": {"level": level},
        "content": [{"type": "text", "text": text}],
    }


def _adf_bullet_list(items: list[str]) -> dict:
    return {
        "type": "bulletList",
        "content": [
            {
                "type": "listItem",
                "content": [_adf_paragraph(item)]
            }
            for item in items if item
        ],
    }


def _adf_doc(blocks: list[dict]) -> dict:
    return {"type": "doc", "version": 1, "content": [b for b in blocks if b]}


def _build_parent_description_adf(document: dict) -> dict:
    pm_id = document.get("postmortem_id", "?")
    cluster_id = document.get("cluster_id", "?")
    verdict_block = document.get("verdict") or {}
    pv = verdict_block.get("platform_verdict", "?")
    confidence = verdict_block.get("confidence", 0.0)
    materiality = verdict_block.get("materiality_assessment", "?")

    blocks = [
        _adf_paragraph(f"Postmortem ID: {pm_id}"),
        _adf_paragraph(f"Cluster: {cluster_id}"),
        _adf_paragraph(f"Verdict: {pv} (confidence {confidence:.2f})"),
        _adf_paragraph(f"Materiality: {materiality}"),
        _adf_heading("Sections"),
        _adf_bullet_list([
            f"{sec.get('section_id')} — {sec.get('v1_status')}"
            for sec in (document.get("sections") or [])
        ]),
        _adf_heading("Note"),
        _adf_paragraph(
            "This Jira issue was created from a JanuSec postmortem. The full "
            "postmortem with evidence row references and bitemporal trace lives "
            "in JanuSec; this issue is the workflow tracker. Child tasks below "
            "represent corrective actions, regulatory notifications, and risk "
            "register reviews derived from the postmortem."
        ),
    ]
    return _adf_doc(blocks)


def _action_description_adf(action: dict, document: dict) -> dict:
    blocks = [
        _adf_paragraph(action.get("description", "") or ""),
        _adf_heading("Triggered by"),
        _adf_paragraph(f"Control failure: {action.get('triggered_by_failure', '?')}"),
        _adf_heading("Framework references"),
        _adf_bullet_list(action.get("framework_refs") or []),
        _adf_heading("Verification evidence required"),
        _adf_paragraph(action.get("verification_evidence_required", "TBD")),
        _adf_paragraph(f"From JanuSec postmortem: {document.get('postmortem_id', '?')} "
                       f"(action_id={action.get('action_id', '?')})"),
    ]
    return _adf_doc(blocks)


def _regulatory_description_adf(trigger: dict, document: dict) -> dict:
    blocks = [
        _adf_paragraph(f"{trigger.get('name', '?')} — {trigger.get('jurisdiction', '?')}"),
        _adf_paragraph(f"Clock: {trigger.get('clock_human', '?')} from {trigger.get('starts_from', '?')}"),
        _adf_paragraph(f"Deadline: {trigger.get('deadline', '?')}"),
        _adf_paragraph(f"Hours remaining at task creation: {trigger.get('hours_remaining', '?')}"),
        _adf_heading("Rationale"),
        _adf_paragraph(trigger.get("rationale", "")),
        _adf_heading("⚠ HUMAN-SUBMIT ONLY"),
        _adf_paragraph(
            "JanuSec NEVER auto-submits to a regulator. The pre-filled "
            "notification form is available for human review at the JanuSec "
            "postmortem URL. The customer's authorised person must review, "
            "make the materiality determination, and submit through the "
            "regulator's official channel. Do not paste pre-fill content into "
            "the regulator portal without legal review."
        ),
        _adf_paragraph(f"From JanuSec postmortem: {document.get('postmortem_id', '?')}"),
    ]
    return _adf_doc(blocks)


def _risk_description_adf(candidate: dict, document: dict) -> dict:
    blocks = [
        _adf_paragraph(candidate.get("description", "")),
        _adf_paragraph(f"Severity: {candidate.get('severity', '?')}"),
        _adf_heading("Affected data classes"),
        _adf_bullet_list(candidate.get("affected_data_classes") or []),
        _adf_paragraph(candidate.get("review_action", "")),
        _adf_paragraph(f"From JanuSec postmortem: {document.get('postmortem_id', '?')}"),
    ]
    return _adf_doc(blocks)


# ─────────────────────────────────────────────────────────────────────────────
#  Auth + HTTP
# ─────────────────────────────────────────────────────────────────────────────


def _build_auth_handle(auth_config: dict):
    method = (auth_config.get("method") or "").lower()
    if method == "basic_auth":
        email = auth_config.get("email") or ""
        token = auth_config.get("api_token") or ""
        if not email or not token:
            return None
        if requests is None:
            return None
        return requests.auth.HTTPBasicAuth(email, token)
    if method == "bearer_token":
        token = auth_config.get("token") or ""
        if not token:
            return None
        # Return a sentinel that _create_issue knows to interpret as Bearer.
        return ("__bearer__", token)
    return None


def _create_issue(base_url: str, payload: dict, auth) -> dict:
    """POST /rest/api/3/issue. Returns {success, issue_key, issue_id, error}."""
    if requests is None:
        return {"success": False, "error": "requests not available"}

    url = f"{base_url}/rest/api/3/issue"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    # Strip internal-only keys from payload before sending.
    body = {"fields": payload.get("fields") or {}}

    try:
        if isinstance(auth, tuple) and auth[0] == "__bearer__":
            headers["Authorization"] = f"Bearer {auth[1]}"
            r = requests.post(url, json=body, headers=headers, timeout=30)
        else:
            r = requests.post(url, json=body, headers=headers, auth=auth, timeout=30)

        if r.status_code in (200, 201):
            data = r.json() or {}
            return {
                "success":   True,
                "issue_key": data.get("key"),
                "issue_id":  data.get("id"),
            }
        return {
            "success": False,
            "error":   f"jira_http_{r.status_code}",
            "body":    r.text[:500],
        }
    except Exception as exc:
        return {"success": False, "error": f"jira_exception:{exc}"}


# ─────────────────────────────────────────────────────────────────────────────
#  Small helpers
# ─────────────────────────────────────────────────────────────────────────────


def _build_labels(document: dict, scope: str, extra: list[str] | None = None) -> list[str]:
    """Stable label scheme — tenants can filter on these in JQL."""
    labels = ["janusec", "postmortem"]
    verdict = (document.get("verdict") or {}).get("platform_verdict", "").lower().replace(" ", "-")
    if verdict:
        labels.append(verdict)
    if scope:
        labels.append(scope)
    for e in (extra or []):
        if e:
            labels.append(str(e).lower().replace(" ", "-"))
    # Jira labels can't contain spaces; deduplicate.
    return sorted(set(l for l in labels if l))


def _verdict_to_jira_priority(verdict: str) -> dict:
    v = (verdict or "").upper()
    if v in ("VALIDATED_BREACH", "CONFIRMED_INTRUSION"):
        return {"name": "Highest"}
    if v == "SUSPECTED_BREACH":
        return {"name": "High"}
    return {"name": "Medium"}


def _priority_to_jira(p: str) -> dict:
    return {
        "P1": {"name": "Highest"},
        "P2": {"name": "High"},
        "P3": {"name": "Medium"},
        "P4": {"name": "Low"},
    }.get((p or "P3").upper(), {"name": "Medium"})


def _due_date_iso(days_from_now: int | None) -> str | None:
    if days_from_now is None:
        return None
    try:
        d = datetime.now(timezone.utc) + timedelta(days=int(days_from_now))
        return d.date().isoformat()
    except (TypeError, ValueError):
        return None


def _deadline_iso_to_due_date(deadline_iso: str | None, hours_buffer: int = 24) -> str | None:
    """Set Jira due date a buffer before the actual regulatory deadline so
    the customer's team has time to review before submission."""
    if not deadline_iso:
        return None
    try:
        d = datetime.fromisoformat(deadline_iso.replace("Z", "+00:00"))
        d = d - timedelta(hours=hours_buffer)
        return d.date().isoformat()
    except (ValueError, TypeError):
        return None


__all__ = ["push"]
