"""
SOCI Act Critical Infrastructure Incident Notification Pre-fill
================================================================

Security of Critical Infrastructure Act 2018 (Cth) Part 2B — Mandatory
Reporting.

CLOCKS
------
- 'Significant' incident: 12 hours (real and material impact on availability /
  integrity of CI asset)
- 'Other reportable' incident: 72 hours

APPLICABILITY GATE
------------------
Only applies if entity is a responsible entity for a critical infrastructure
asset. The module checks ``entity_context.soci_sectors`` from the postmortem
to determine if this trigger applies. If the list is empty, returns
``applicable: false`` and the customer's compliance team should not file.

NEVER AUTO-SUBMITS
------------------
Submitted via ASD's ReportCyber portal or designated ASD CI portal.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def prefill(*, document: dict, tenant_config: dict) -> dict:
    from src.postmortem.postmortem_assembler import get_computed_section

    s1 = get_computed_section(document, "s1_incident_lifecycle") or {}
    s2 = get_computed_section(document, "s2_threat_reconstruction") or {}

    narrative_passthrough = tenant_config.get("_narrative_passthrough") or {}
    affected_data = narrative_passthrough.get("affected_data") or {}
    affected_principals = narrative_passthrough.get("affected_principals") or {}
    attacker_infra = narrative_passthrough.get("attacker_infrastructure") or {}
    discovery = narrative_passthrough.get("discovery") or {}

    entity_context = tenant_config.get("_entity_context_passthrough") or {}
    soci_sectors = entity_context.get("soci_sectors") or []

    # Applicability check ── if no SOCI sectors registered, this trigger
    # doesn't apply to the entity. Return early with applicable=false.
    if not soci_sectors:
        return {
            "regulator":                "au_soci",
            "regulator_name":           "Australian Signals Directorate",
            "applicable":               False,
            "applicability_rationale":  "entity_context.soci_sectors is empty — entity is not a responsible entity for any registered critical infrastructure asset.",
            "human_review_required":    True,
            "auto_submit_allowed":      False,
            "fields":                   {},
            "field_provenance":         {},
            "human_review_checklist":   ["Confirm whether the entity is a responsible entity under SOCI Act."],
        }

    ciso = (tenant_config.get("ciso") or {})

    fields: dict[str, Any] = {
        # Entity identification
        "organisation_name":             tenant_config.get("entity_name"),
        "abn":                           tenant_config.get("abn"),
        "sector":                        soci_sectors[0],
        "all_sectors":                   soci_sectors,
        "critical_infrastructure_asset_name": entity_context.get("ci_asset_name"),
        "critical_infrastructure_asset_id":   entity_context.get("ci_asset_id"),

        # Contact (CISO or designated CI security officer)
        "contact_name":                  ciso.get("name"),
        "contact_role":                  ciso.get("role", "CISO"),
        "contact_email":                 ciso.get("email"),
        "contact_phone":                 ciso.get("phone"),

        # Incident details
        "incident_type":                 "cyber_security_incident",
        "incident_category":             _category_from_kc(s2.get("kill_chain_stage")),
        "date_incident_started":         discovery.get("first_evidence_at"),
        "date_incident_detected":        discovery.get("when"),
        "date_of_this_report":           None,  # set at submission

        "description_of_incident":       _description(s1, s2, document),
        "systems_affected":              _systems_prose(affected_principals),
        "services_impacted":             entity_context.get("ci_services") or [],
        "data_exfiltrated":              affected_data.get("classes") or [],
        "threat_actor_assessment":       _threat_actor_prose(attacker_infra, s2),

        "immediate_actions_taken":       _contain_prose(s1),
        "assistance_required_from_asd":  False,  # human flips to true if needed
        "law_enforcement_notified":      False,
        "other_agencies_notified":       _other_agencies(document),
    }

    field_provenance = {
        "sector":                        ["entity_context.soci_sectors"],
        "date_incident_started":         ["narrative.discovery.first_evidence_at"],
        "date_incident_detected":        ["narrative.discovery.when"],
        "description_of_incident":       ["section_s1.auto_output", "section_s2.auto_output"],
        "systems_affected":              ["narrative.affected_principals"],
        "data_exfiltrated":              ["narrative.affected_data.classes"],
        "threat_actor_assessment":       ["narrative.attacker_infrastructure"],
    }

    return {
        "regulator":                "au_soci",
        "regulator_name":           "Australian Signals Directorate (Home Affairs)",
        "form_version":             "asd_cyber_incident_reporting_2024",
        "notification_scheme":      "Security of Critical Infrastructure Act 2018 (Cth), Part 2B",
        "applicable":               True,
        "clock_seconds_significant":     43200,    # 12h
        "clock_human_significant":       "12h",
        "clock_seconds_other_reportable": 259200,  # 72h
        "clock_human_other_reportable":   "72h",
        "human_review_required":    True,
        "auto_submit_allowed":      False,
        "submission_method":        "manual_form_with_review",
        "submission_endpoint":      "https://www.cyber.gov.au/report-and-recover/report",
        "submission_note":          "Determine whether incident qualifies as 'significant' (12h) or 'other reportable' (72h) before submitting.",
        "fields":                   fields,
        "field_provenance":         field_provenance,
        "human_review_checklist":   _soci_review_checklist(),
        "missing_required_fields":  [k for k, v in fields.items() if v in (None, "", []) and k in _SOCI_REQUIRED],
    }


# ─────────────────────────────────────────────────────────────────────────────
#  Prose helpers
# ─────────────────────────────────────────────────────────────────────────────


def _category_from_kc(kc_stage: str | None) -> str:
    if not kc_stage:
        return "cyber_security_incident"
    kc = kc_stage.lower()
    if "exfiltration" in kc:
        return "data_breach"
    if "encryption" in kc or "ransom" in kc:
        return "ransomware"
    if "command_and_control" in kc or "c2" in kc:
        return "intrusion"
    return "cyber_security_incident"


def _description(s1: dict, s2: dict, document: dict) -> str:
    pv = (document.get("verdict") or {}).get("platform_verdict", "?")
    techniques = s2.get("mitre_techniques") or []
    detect = s1.get("detect") or {}
    parts = [f"Verdict: {pv}."]
    if detect.get("method"):
        parts.append(f"Detected via {detect['method']}.")
    if techniques:
        parts.append(f"MITRE ATT&CK techniques: {', '.join(techniques[:8])}.")
    text = " ".join(parts)
    if len(text) > 400:
        text = text[:397] + "..."
    return text


def _systems_prose(affected_principals: dict) -> str:
    hosts = affected_principals.get("hosts") or []
    cloud_roles = affected_principals.get("cloud_roles") or []
    parts: list[str] = []
    if hosts:
        parts.append(f"{len(hosts)} host(s): {', '.join(hosts[:5])}.")
    if cloud_roles:
        parts.append(f"{len(cloud_roles)} cloud role(s) implicated.")
    return " ".join(parts) or "Systems under investigation."


def _threat_actor_prose(infra: dict, s2: dict) -> str:
    asns = infra.get("asns") or []
    countries = infra.get("countries") or []
    actor = s2.get("threat_actor_profile")
    parts: list[str] = []
    if actor:
        parts.append(str(actor))
    if countries:
        parts.append(f"Source countries observed: {', '.join(countries[:3])}.")
    if asns:
        parts.append(f"Source ASNs: {', '.join(asns[:5])}.")
    return " ".join(parts) or "Threat actor attribution under analysis."


def _contain_prose(s1: dict) -> str:
    contain = s1.get("contain") or {}
    actions = contain.get("actions") or []
    if not actions:
        return "Containment actions in progress."
    return "; ".join(str(a)[:150] for a in actions[:5])


def _other_agencies(document: dict) -> list[str]:
    """Cross-reference other regulatory submissions to declare to ASD."""
    others: list[str] = []
    for sub in (document.get("regulator_submissions") or []):
        rid = sub.get("regulator")
        if rid == "au_ndb":
            others.append("OAIC (NDB)")
        elif rid == "au_apra_cps234":
            others.append("APRA (CPS 234)")
    return others


_SOCI_REQUIRED = {
    "organisation_name", "abn", "sector",
    "contact_name", "contact_email",
    "date_incident_detected", "description_of_incident",
}


def _soci_review_checklist() -> list[str]:
    return [
        "Confirm entity is a responsible entity for a critical infrastructure asset under SOCI Act",
        "Determine incident severity: 'significant' (12h clock) vs 'other reportable' (72h clock)",
        "Verify sector classification matches the registered CI asset",
        "Confirm systems_affected includes the CI asset itself, not just peripheral systems",
        "Review threat_actor_assessment for classification accuracy before submission to ASD",
        "ASD may follow up with threat intelligence exchange request — prepare IR team for engagement",
        "Cross-reference other agency notifications (OAIC, APRA) — declare in 'other_agencies_notified'",
    ]


__all__ = ["prefill"]
