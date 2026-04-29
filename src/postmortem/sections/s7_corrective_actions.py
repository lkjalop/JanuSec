"""
Section 7 — Corrective Actions
==============================

v1 status: FULLY_IMPLEMENTED

Generates corrective action items from the control failure register. Each
P1 control failure produces one corrective action with:
  - Action title (short, imperative)
  - Description with framework references and rationale
  - Owner role (e.g. "Identity & Access Team")
  - Target due-days from incident close
  - Verification evidence required

These corrective actions become Jira/ServiceNow child tasks via the ITSM
push module, so the customer's existing ticket workflow handles execution.

ACTION TEMPLATES
----------------
Action templates are keyed by (framework, control_id_pattern). When a
control failure matches a template, the template generates the action.
Unmatched controls produce a generic action that the analyst customises
during sign-off.

INPUTS
------
- register['control_failures_by_framework']
- narrative['affected_principals'] — for owner role inference
- narrative['attacker_infrastructure'] — for IOC blocking actions

OUTPUTS
-------
- actions: list of corrective action records
- ownership_summary: counts by owner role
- coverage_check: which control failures DID NOT generate an action (to surface gaps)
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
#  Corrective action templates
# ─────────────────────────────────────────────────────────────────────────────
# Keyed by (framework, control_id_prefix).  control_id_prefix matches via
# startswith(), so 'A.5' matches A.5.15 and A.5.17 but not A.8.5.
#
# Each template produces a partial action dict; finalise_action() fills in
# the dynamic fields (action_id, evidence_refs, due dates).

_ACTION_TEMPLATES: list[dict] = [
    {
        "match": ("iso27001", "A.5.15"),
        "title": "Tighten user access management process",
        "description": "Quarterly access certification for all federated identities, "
                       "with documented exceptions and management sign-off.",
        "owner_role":      "Identity & Access Team",
        "due_days":        30,
        "verification":    "Access review records for the next two cycles.",
        "framework_refs":  ["iso27001:A.5.15", "iso27001:A.5.16", "iso27001:A.5.18"],
    },
    {
        "match": ("iso27001", "A.5.17"),
        "title": "Implement privileged access management for break-glass and admin accounts",
        "description": "PAM solution covering all privileged accounts with session "
                       "recording and time-bound access.",
        "owner_role":      "Identity & Access Team",
        "due_days":        60,
        "verification":    "PAM deployment evidence + PAM session log review.",
        "framework_refs":  ["iso27001:A.5.17", "essential_eight:RESTRICT_ADMIN_PRIV_ML2"],
    },
    {
        "match": ("iso27001", "A.8.5"),
        "title": "Enforce phishing-resistant MFA on all federated and privileged identities",
        "description": "Migrate from SMS/push MFA to FIDO2/WebAuthn or hardware tokens. "
                       "Document and review any exception policies.",
        "owner_role":      "Identity & Access Team",
        "due_days":        45,
        "verification":    "MFA enrolment report; exception register signed by CISO.",
        "framework_refs":  ["iso27001:A.8.5", "essential_eight:MFA_ML3"],
    },
    {
        "match": ("iso27001", "A.8.22"),
        "title": "Review network segmentation between production zones",
        "description": "Audit east-west traffic paths between segments hosting "
                       "crown-jewel data assets. Implement microsegmentation where gaps exist.",
        "owner_role":      "Network Security Team",
        "due_days":        90,
        "verification":    "Updated network architecture diagram + segmentation test results.",
        "framework_refs":  ["iso27001:A.8.22"],
    },
    {
        "match": ("essential_eight", "MFA"),
        "title": "Raise MFA Maturity Level toward ML3",
        "description": "Phishing-resistant MFA for privileged users, internet-facing "
                       "services, and customer-facing services per ASD ACSC ML3 criteria.",
        "owner_role":      "Identity & Access Team",
        "due_days":        45,
        "verification":    "Updated Essential Eight maturity self-assessment.",
        "framework_refs":  ["essential_eight:MFA_ML3"],
    },
    {
        "match": ("essential_eight", "PATCH_OS"),
        "title": "Reduce OS patch latency to ML2 / ML3 tolerance",
        "description": "48 hours for internet-facing systems; 1 month for internal. "
                       "Validate via vulnerability scan cadence.",
        "owner_role":      "Endpoint / Server Operations",
        "due_days":        90,
        "verification":    "Vuln scan reports showing reduced age-of-vulnerability metrics.",
        "framework_refs":  ["essential_eight:PATCH_OS_ML2"],
    },
    {
        "match": ("apra_cps234", ""),
        "title": "Brief the Board on the incident in accordance with CPS 234 §13–14",
        "description": "Material information security incident requires Board-level "
                       "awareness. Prepare a CPS 234-compliant briefing pack.",
        "owner_role":      "CISO + Company Secretary",
        "due_days":        14,
        "verification":    "Board minutes referencing the incident briefing.",
        "framework_refs":  ["apra_cps234:§13", "apra_cps234:§14"],
    },
    {
        "match": ("nist_csf", "PR.AA"),
        "title": "Strengthen identity authentication controls (NIST CSF PR.AA)",
        "description": "Review identity proofing, credential management, and "
                       "access management against NIST CSF 2.0 PR.AA-* outcomes.",
        "owner_role":      "Identity & Access Team",
        "due_days":        60,
        "verification":    "PR.AA self-assessment + remediation plan.",
        "framework_refs":  ["nist_csf:PR.AA-01", "nist_csf:PR.AA-05"],
    },
]


def build_s7_corrective_actions(
    *,
    cluster: dict,
    narrative: dict,
    register: dict,
    evidence_rows: list[dict],
    tenant_config: dict,
    entity_context: dict,
) -> dict:
    cf = (register or {}).get("control_failures_by_framework") or {}

    actions: list[dict] = []
    matched_failures: set[str] = set()
    next_id = 1

    # First pass: template-matched actions.
    for fw, recs in cf.items():
        if fw == "unmapped_techniques":
            continue
        for rec in recs:
            template = _find_template(fw, rec.get("control_id", ""))
            if not template:
                continue
            action = _instantiate_template(template, rec, fw, next_id)
            actions.append(action)
            matched_failures.add(_failure_key(fw, rec.get("control_id", "")))
            next_id += 1

    # Add IOC-blocking action if attacker infra was identified.
    infra_action = _build_ioc_block_action(narrative, next_id)
    if infra_action:
        actions.append(infra_action)
        next_id += 1

    # Add evidence preservation action if not already in the list.
    actions.append(_build_evidence_preservation_action(narrative, next_id))
    next_id += 1

    # Second pass: cover unmatched failures with a generic action so analyst
    # has something to start from.
    coverage_gaps: list[dict] = []
    for fw, recs in cf.items():
        if fw == "unmapped_techniques":
            continue
        for rec in recs:
            key = _failure_key(fw, rec.get("control_id", ""))
            if key in matched_failures:
                continue
            if (rec.get("severity") or "").lower() in ("critical", "high"):
                actions.append(_generic_action(rec, fw, next_id))
                next_id += 1
                matched_failures.add(key)
            else:
                coverage_gaps.append({
                    "framework":    fw,
                    "control_id":   rec.get("control_id"),
                    "severity":     rec.get("severity"),
                    "reason":       "No template matched; severity below auto-generate threshold.",
                })

    # Deduplicate actions with the same title.
    actions = _dedupe_by_title(actions)

    # Sort by priority (P1 first), then by due_days ascending.
    _PRI = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    actions.sort(key=lambda a: (_PRI.get(a.get("priority", "P3"), 9),
                                 a.get("due_days", 999)))

    ownership_summary: dict[str, int] = {}
    for a in actions:
        owner = a.get("owner_role") or "Unassigned"
        ownership_summary[owner] = ownership_summary.get(owner, 0) + 1

    auto_output = {
        "actions":            actions,
        "action_count":       len(actions),
        "ownership_summary":  ownership_summary,
        "coverage_gaps":      coverage_gaps,
    }
    return {
        "title": "Corrective Actions",
        "auto_output": auto_output,
    }


def _find_template(framework: str, control_id: str) -> dict | None:
    for t in _ACTION_TEMPLATES:
        fw_key, cid_prefix = t["match"]
        if fw_key != framework:
            continue
        # Empty prefix means "any control_id under this framework".
        if not cid_prefix or control_id.startswith(cid_prefix):
            return t
    return None


def _instantiate_template(template: dict, rec: dict, framework: str, action_id: int) -> dict:
    severity = (rec.get("severity") or "moderate").lower()
    priority = _severity_to_priority(severity)
    return {
        "action_id":           f"ca-{action_id:03d}",
        "title":                template["title"],
        "description":          template["description"],
        "framework_refs":       list(template.get("framework_refs") or []),
        "triggered_by_failure": f"{framework}:{rec.get('control_id', '')}",
        "owner_role":           template["owner_role"],
        "owner":                None,   # specific person assigned at signoff
        "priority":             priority,
        "due_days":             template["due_days"],
        "due_date":             None,   # filled by ITSM push at incident close
        "verification_evidence_required": template["verification"],
        "evidence_refs":        list(rec.get("evidence_refs") or []),
        "status":               "DRAFT",
    }


def _generic_action(rec: dict, framework: str, action_id: int) -> dict:
    """For unmatched control failures of high/critical severity."""
    return {
        "action_id":           f"ca-{action_id:03d}",
        "title":                f"Remediate {framework} {rec.get('control_id')} control gap",
        "description":          f"Control failure observed: {rec.get('control_name', rec.get('control_id'))}. "
                                f"Analyst to specify remediation approach.",
        "framework_refs":       [f"{framework}:{rec.get('control_id', '')}"],
        "triggered_by_failure": f"{framework}:{rec.get('control_id', '')}",
        "owner_role":           "Security Engineering",
        "owner":                None,
        "priority":             _severity_to_priority(rec.get("severity") or "moderate"),
        "due_days":             60,
        "due_date":             None,
        "verification_evidence_required": "TBD — analyst defines at sign-off.",
        "evidence_refs":        list(rec.get("evidence_refs") or []),
        "status":               "DRAFT",
    }


def _build_ioc_block_action(narrative: dict, action_id: int) -> dict | None:
    infra = narrative.get("attacker_infrastructure") or {}
    ips = list(infra.get("external_ips") or [])
    asns = list(infra.get("asns") or [])
    if not ips and not asns:
        return None
    return {
        "action_id":           f"ca-{action_id:03d}",
        "title":               "Block attacker IOCs at perimeter and EDR",
        "description":         f"Add to perimeter firewall + EDR IOC lists: "
                               f"{len(ips)} IPs, {len(asns)} ASNs identified in this incident.",
        "framework_refs":      ["iso27001:A.8.20"],
        "triggered_by_failure": "ioc_response",
        "owner_role":          "SOC",
        "owner":               None,
        "priority":            "P1",
        "due_days":            1,   # immediate
        "due_date":            None,
        "verification_evidence_required": "Firewall rules + EDR IOC list snapshots showing the additions.",
        "evidence_refs":       [],
        "status":              "DRAFT",
        "iocs": {
            "ips":  ips[:20],
            "asns": asns[:10],
        },
    }


def _build_evidence_preservation_action(narrative: dict, action_id: int) -> dict:
    return {
        "action_id":           f"ca-{action_id:03d}",
        "title":               "Preserve forensic evidence (ISO 27037)",
        "description":         "Disk images, memory dumps, log archives, and cloud audit "
                               "logs for affected hosts and accounts. Maintain chain of custody.",
        "framework_refs":      ["iso27001:A.5.28", "iso27037:§7"],
        "triggered_by_failure": "forensic_preservation",
        "owner_role":          "DFIR Lead",
        "owner":               None,
        "priority":            "P1",
        "due_days":            1,
        "due_date":             None,
        "verification_evidence_required": "Evidence inventory with hash values, chain-of-custody log.",
        "evidence_refs":       [],
        "status":              "DRAFT",
    }


def _severity_to_priority(severity: str) -> str:
    return {
        "critical": "P1",
        "high":     "P1",
        "moderate": "P2",
        "low":      "P3",
    }.get((severity or "").lower(), "P3")


def _failure_key(framework: str, control_id: str) -> str:
    return f"{framework}:{control_id}"


def _dedupe_by_title(actions: list[dict]) -> list[dict]:
    """Multiple control failures can match the same template (e.g. several
    A.8.5 failures all map to 'Enforce phishing-resistant MFA'). Merge them
    into one action with combined evidence_refs and framework_refs."""
    seen: dict[str, dict] = {}
    for a in actions:
        title = a.get("title", "")
        if title not in seen:
            seen[title] = a
        else:
            target = seen[title]
            target["evidence_refs"] = sorted(set(
                list(target.get("evidence_refs") or []) +
                list(a.get("evidence_refs") or [])
            ))
            target["framework_refs"] = sorted(set(
                list(target.get("framework_refs") or []) +
                list(a.get("framework_refs") or [])
            ))
            # Take the higher priority (lower P-number wins).
            tp = target.get("priority", "P3")
            ap = a.get("priority", "P3")
            if ap < tp:
                target["priority"] = ap
            # Take the shorter due_days.
            target["due_days"] = min(target.get("due_days", 999), a.get("due_days", 999))
    return list(seen.values())
