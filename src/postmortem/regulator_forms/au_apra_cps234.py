"""
APRA CPS 234 Material Information Security Incident Notification Pre-fill
==========================================================================

Prudential Standard CPS 234 paragraph 36 — Material Information Security
Incident Notification.

CLOCK
-----
72 hours from when the entity becomes aware of a material information
security incident. Plus 10 business days for material control weakness
notification (separate trigger).

FORMAT
------
APRA does NOT have a structured online form for CPS 234 notifications.
Notification is prose-style submitted via APRA Connect or directly to the
responsible APRA supervisor. This module produces a structured prose draft
the CISO reviews and submits.

NEVER AUTO-SUBMITS
------------------
Always returns a draft for human review. Submission must be by or on
behalf of the Board or a delegated officer.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def prefill(*, document: dict, tenant_config: dict) -> dict:
    from src.postmortem.postmortem_assembler import get_computed_section

    s1 = get_computed_section(document, "s1_incident_lifecycle") or {}
    s2 = get_computed_section(document, "s2_threat_reconstruction") or {}
    s3 = get_computed_section(document, "s3_control_failures") or {}
    s7 = get_computed_section(document, "s7_corrective_actions") or {}

    narrative_passthrough = tenant_config.get("_narrative_passthrough") or {}
    affected_data = narrative_passthrough.get("affected_data") or {}
    affected_principals = narrative_passthrough.get("affected_principals") or {}
    discovery = narrative_passthrough.get("discovery") or {}

    ciso = (tenant_config.get("ciso") or {})

    fields: dict[str, Any] = {
        # Entity identification
        "regulated_entity_name":  tenant_config.get("entity_name"),
        "regulated_entity_abn":   tenant_config.get("abn"),
        "apra_entity_number":     tenant_config.get("apra_entity_number"),
        "responsible_supervisor_contact": tenant_config.get("apra_supervisor"),

        # Contact (CISO)
        "contact_person_name":    ciso.get("name"),
        "contact_person_role":    ciso.get("role", "CISO"),
        "contact_person_email":   ciso.get("email"),
        "contact_person_phone":   ciso.get("phone"),

        # Dates
        "date_incident_occurred":   _date_only(discovery.get("first_evidence_at")),
        "date_incident_discovered": _date_only(discovery.get("when")),
        "date_of_this_notification": None,  # set by human at submission time

        # Incident description (prose)
        "nature_of_incident":           _nature_prose(s1, s2, document),
        "information_assets_affected":  _assets_prose(affected_data),
        "third_parties_affected":       _third_parties_prose(affected_principals),
        "impact_assessment":            _impact_prose(affected_data, document),

        "immediate_actions_taken":      _contain_prose(s1),
        "planned_remediation":          _planned_prose(s7),
        "root_cause_assessment":        _root_cause_or_pending(s1),
        "estimated_time_to_remediation": _max_due_days(s7),

        # Compliance posture context
        "control_failures_summary":     _failures_summary(s3),
        "frameworks_impacted":          _frameworks_impacted(s3),
        "material_impact_rationale":    _material_impact_rationale(affected_data, document),

        # Update commitments
        "further_updates_expected":     True,
        "next_update_expected_at":      None,  # set at submission
    }

    field_provenance = {
        "nature_of_incident":            ["section_s2.auto_output", "section_s1.auto_output"],
        "information_assets_affected":   ["narrative.affected_data"],
        "immediate_actions_taken":       ["section_s1.auto_output.contain"],
        "planned_remediation":           ["section_s7.auto_output.actions"],
        "control_failures_summary":      ["section_s3.auto_output.summary"],
        "material_impact_rationale":     ["narrative.affected_data", "verdict"],
    }

    return {
        "regulator":                "au_apra_cps234",
        "regulator_name":           "Australian Prudential Regulation Authority",
        "form_version":             "apra_cps234_notification_prose_2024",
        "notification_scheme":      "Prudential Standard CPS 234 — paragraph 36",
        "clock_seconds":            259200,    # 72 hours
        "clock_human":              "72h",
        "human_review_required":    True,
        "auto_submit_allowed":      False,
        "submission_method":        "manual_form_with_review",
        "submission_channel":       "APRA Connect or direct submission to responsible APRA supervisor",
        "submission_note":          "Contact APRA supervisor directly if APRA Connect is unavailable within the 72h window.",
        "fields":                   fields,
        "field_provenance":         field_provenance,
        "human_review_checklist":   _apra_review_checklist(),
        "missing_required_fields":  [k for k, v in fields.items() if v in (None, "", []) and k in _APRA_REQUIRED],
    }


# ─────────────────────────────────────────────────────────────────────────────
#  Prose helpers
# ─────────────────────────────────────────────────────────────────────────────


def _date_only(iso: str | None) -> str | None:
    return iso.split("T")[0] if iso else None


def _nature_prose(s1: dict, s2: dict, document: dict) -> str:
    pv = (document.get("verdict") or {}).get("platform_verdict", "?")
    techniques = s2.get("mitre_techniques") or []
    kc = s2.get("kill_chain_stage", "?")
    detect = s1.get("detect") or {}
    parts = [
        f"Material information security incident — verdict: {pv}.",
        f"Kill-chain stage observed: {kc}.",
    ]
    if techniques:
        parts.append(f"MITRE ATT&CK techniques: {', '.join(techniques[:10])}.")
    if detect.get("method"):
        parts.append(f"Detection method: {detect['method']} on {detect.get('detected_at', '?')}.")
    return " ".join(parts)


def _assets_prose(affected_data: dict) -> str:
    tables = affected_data.get("tables") or []
    classes = affected_data.get("classes") or []
    sens = affected_data.get("sensitivity", "unknown")
    parts = [f"Sensitivity: {sens}."]
    if classes:
        parts.append(f"Data classes touched: {', '.join(classes[:6])}.")
    if tables:
        parts.append(f"Information assets affected: {len(tables)} table(s) — "
                     f"top: {', '.join(tables[:3])}.")
    return " ".join(parts)


def _third_parties_prose(affected_principals: dict) -> str:
    svc = affected_principals.get("service_accounts") or []
    cloud = affected_principals.get("cloud_roles") or []
    parts: list[str] = []
    if svc:
        parts.append(f"{len(svc)} service account(s) implicated.")
    if cloud:
        parts.append(f"{len(cloud)} cloud role(s) implicated.")
    return " ".join(parts) or "No third-party service providers identified at this time. Pending review."


def _impact_prose(affected_data: dict, document: dict) -> str:
    sens = affected_data.get("sensitivity", "unknown")
    rc = affected_data.get("record_count_estimate")
    pv = (document.get("verdict") or {}).get("platform_verdict", "?")
    parts = [f"Verdict: {pv}.", f"Sensitivity: {sens}."]
    if rc:
        parts.append(f"Estimated records potentially affected: {rc:,}.")
    if affected_data.get("crown_jewel_touched"):
        parts.append("Crown-jewel data class confirmed.")
    return " ".join(parts)


def _contain_prose(s1: dict) -> str:
    contain = s1.get("contain") or {}
    actions = contain.get("actions") or []
    if not actions:
        return "Containment actions in progress; full details to be supplied at human review."
    return "Actions taken: " + "; ".join(str(a)[:200] for a in actions[:5])


def _planned_prose(s7: dict) -> str:
    p1 = [a for a in (s7.get("actions") or []) if a.get("priority") == "P1"]
    if not p1:
        return "Corrective action plan under development."
    titles = [a.get("title", "") for a in p1[:5]]
    return "; ".join(titles)


def _root_cause_or_pending(s1: dict) -> str:
    pir = s1.get("post_incident_review") or {}
    rc = pir.get("root_cause")
    return rc if rc else "Root cause assessment pending; update to follow."


def _max_due_days(s7: dict) -> str:
    actions = s7.get("actions") or []
    if not actions:
        return "TBD"
    max_due = max((a.get("due_days", 0) for a in actions), default=0)
    return f"~{max_due} days from incident close"


def _failures_summary(s3: dict) -> str:
    summary = s3.get("summary") or {}
    fc = summary.get("failed_control_count", 0)
    cc = summary.get("critical_control_count", 0)
    return f"{fc} control failures, {cc} critical."


def _frameworks_impacted(s3: dict) -> str:
    summary = s3.get("summary") or {}
    fws = summary.get("frameworks_with_failures") or []
    return ", ".join(fws) if fws else "Pending control mapping completion."


def _material_impact_rationale(affected_data: dict, document: dict) -> str:
    pv = (document.get("verdict") or {}).get("platform_verdict", "?")
    crown = affected_data.get("crown_jewel_touched")
    rc = affected_data.get("record_count_estimate") or 0
    parts: list[str] = []
    if pv in ("VALIDATED_BREACH", "CONFIRMED_INTRUSION"):
        parts.append("Platform verdict: validated breach.")
    if crown:
        parts.append("Crown-jewel data class confirmed.")
    if rc > 1000:
        parts.append(f"~{rc:,} records potentially affected.")
    if not parts:
        parts.append("Materiality determination pending — customer compliance team review required.")
    return " ".join(parts)


_APRA_REQUIRED = {
    "regulated_entity_name", "regulated_entity_abn",
    "contact_person_name", "contact_person_email",
    "date_incident_discovered", "nature_of_incident",
    "information_assets_affected", "impact_assessment",
}


def _apra_review_checklist() -> list[str]:
    return [
        "Verify this entity is a regulated APRA entity under CPS 234 (ADI, insurer, RSE licensee, or affiliated)",
        "Confirm date_of_this_notification is within 72h of date_incident_discovered",
        "Confirm responsible_supervisor_contact is current for this entity type",
        "Review material_impact_rationale — APRA's definition of 'material' is judgment-based, not formulaic",
        "Confirm control_failures_summary is accurate — feeds into APRA's assessment of entity compliance posture",
        "Flag if any third-party service providers are involved — APRA requires notification if a material supplier is implicated",
        "Submission must be by or on behalf of the Board or a delegated officer (CPS 234 §13–14)",
        "Confirm whether a separate 10-business-day material control weakness notification is also required",
    ]


__all__ = ["prefill"]
