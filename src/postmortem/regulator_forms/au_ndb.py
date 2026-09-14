"""
OAIC Notifiable Data Breach (NDB) Pre-fill
==========================================

Privacy Act 1988 (Cth) Part IIIC — Notifiable Data Breaches scheme.

CLOCK
-----
Currently 'as soon as practicable' after the entity becomes aware of an
eligible data breach. Tranche 2 reform proposes a 72-hour outer limit.
This module emits both clock-aware fields so callers can switch the
displayed clock based on tenant config.

NEVER AUTO-SUBMITS
------------------
Returns a structured pre-fill payload with provenance. Customer's authorised
person reviews + submits via the OAIC online portal:
  https://www.oaic.gov.au/privacy/notifiable-data-breaches/report-a-data-breach

INPUTS
------
- document: assembled PostmortemDocument
- tenant_config: per-tenant facts (entity_name, abn, privacy_officer contact,
  etc.) loaded by the caller

OUTPUTS
-------
- regulator: 'au_ndb'
- form_version: pinned identifier
- fields: dict mapping form fields to pre-filled values
- field_provenance: for each pre-filled field, the upstream source(s)
- human_review_checklist: non-skippable review items
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

    # Reach back into the original narrative for fields the sections don't expose.
    # Document doesn't carry the raw narrative; the API endpoint passes it in
    # via tenant_config['_narrative_passthrough'] when the regulator-form
    # endpoint is called. (See src/api/postmortem_endpoints.py.)
    narrative_passthrough = tenant_config.get("_narrative_passthrough") or {}
    affected_data = narrative_passthrough.get("affected_data") or {}
    discovery = narrative_passthrough.get("discovery") or {}

    privacy_officer = (tenant_config.get("privacy_officer") or {})

    # ── Field assembly ───────────────────────────────────────────────────────
    fields: dict[str, Any] = {
        # Entity identification
        "entity_name":           tenant_config.get("entity_name"),
        "abn":                   tenant_config.get("abn"),
        "acn":                   tenant_config.get("acn"),

        # Contact person (privacy officer)
        "contact_person_name":   privacy_officer.get("name"),
        "contact_person_role":   privacy_officer.get("role", "Privacy Officer"),
        "contact_person_email":  privacy_officer.get("email"),
        "contact_person_phone":  privacy_officer.get("phone"),

        # Dates
        "date_aware_of_breach":   _date_only(discovery.get("when")),
        "date_breach_occurred":   _date_only(discovery.get("first_evidence_at")),
        "date_breach_contained":  _contained_date_from_s1(s1),

        # Information involved
        "kinds_of_information_involved":  _ndb_information_kinds(affected_data),
        "sensitive_information_involved": _has_sensitive(affected_data),
        "approximate_individuals_affected": affected_data.get("record_count_estimate"),
        "individuals_at_risk_of_serious_harm": _likely_serious_harm(affected_data),

        # Description
        "description_of_breach":    _description_of_breach(s1, s2, document),
        "how_breach_occurred":      _how_occurred(s1),
        "actions_taken_to_contain": _contain_actions(s1),
        "actions_planned":          _planned_actions(s7),
        "recommendations_to_individuals": _recommendations_to_individuals(affected_data),
        "supporting_evidence_summary": _evidence_summary(s3),
    }

    # ── Field provenance (for the audit trail) ───────────────────────────────
    field_provenance = {
        "entity_name":              ["tenant_config.entity_name"],
        "abn":                      ["tenant_config.abn"],
        "date_aware_of_breach":     ["narrative.discovery.when"],
        "date_breach_occurred":     ["narrative.discovery.first_evidence_at"],
        "kinds_of_information_involved":     ["narrative.affected_data.classes"],
        "approximate_individuals_affected":  ["narrative.affected_data.record_count_estimate"],
        "description_of_breach":    ["section_s1.auto_output", "section_s2.auto_output"],
        "actions_taken_to_contain": ["section_s1.auto_output.contain"],
        "actions_planned":          ["section_s7.auto_output.actions"],
        "recommendations_to_individuals": ["narrative.affected_data.classes"],
        "supporting_evidence_summary":    ["section_s3.auto_output.summary"],
    }

    return {
        "regulator":                "au_ndb",
        "regulator_name":           "Office of the Australian Information Commissioner",
        "form_version":             "ndb_online_form_v3_2024",
        "notification_scheme":      "Privacy Act 1988 (Cth), Part IIIC — Notifiable Data Breaches",
        "clock_seconds":            2592000,    # 30 days (current)
        "clock_human":              "30d",
        "tranche2_72h_clock_proposed": True,    # flag for UI to surface upcoming reform
        "human_review_required":    True,
        "auto_submit_allowed":      False,
        "submission_method":        "manual_form_with_review",
        "submission_endpoint":      "https://www.oaic.gov.au/privacy/notifiable-data-breaches/report-a-data-breach",
        "fields":                   fields,
        "field_provenance":         field_provenance,
        "human_review_checklist":   _ndb_review_checklist(),
        "missing_required_fields":  [k for k, v in fields.items() if v in (None, "", []) and k in _NDB_REQUIRED],
    }


# ─────────────────────────────────────────────────────────────────────────────
#  Field derivation helpers
# ─────────────────────────────────────────────────────────────────────────────


def _date_only(iso_or_none: str | None) -> str | None:
    if not iso_or_none:
        return None
    return str(iso_or_none).split("T")[0]


def _contained_date_from_s1(s1: dict) -> str | None:
    contain = s1.get("contain") or {}
    completed = contain.get("completed_at")
    return _date_only(completed) if completed else None


def _ndb_information_kinds(affected_data: dict) -> list[str]:
    """Map JanuSec data classes to OAIC's enumeration."""
    classes = set(affected_data.get("classes") or [])
    out: list[str] = []
    if "customer_pii" in classes or "personal_information" in classes:
        out.append("Personal information (name, contact)")
    if "financial" in classes or "credit_card" in classes:
        out.append("Financial information")
    if "health_records" in classes or "phi" in classes:
        out.append("Health information")
    if "credentials" in classes:
        out.append("Credentials / authentication data")
    if not out and classes:
        out.append("Other personal information")
    return out


def _has_sensitive(affected_data: dict) -> bool:
    classes = set(affected_data.get("classes") or [])
    return any(c in classes for c in (
        "health_records", "phi", "credentials",
        "biometric", "racial_or_ethnic", "sexual_orientation",
        "religious_beliefs", "political_opinions",
    ))


def _likely_serious_harm(affected_data: dict) -> bool:
    """True if the breach is likely to result in serious harm to individuals
    per the NDB scheme test. This is the customer's legal call ultimately —
    we surface our best reading and flag for human review."""
    if affected_data.get("crown_jewel_touched"):
        return True
    if (affected_data.get("record_count_estimate") or 0) > 1000:
        return True
    if "customer_pii" in (affected_data.get("classes") or []):
        return True
    return False


def _description_of_breach(s1: dict, s2: dict, document: dict) -> str:
    """500-word max description for the NDB form."""
    pv = (document.get("verdict") or {}).get("platform_verdict", "?")
    narrative = s1.get("narrative_summary", "") or ""
    techniques = s2.get("mitre_techniques") or []
    detect = s1.get("detect") or {}

    parts: list[str] = []
    parts.append(f"Verdict: {pv}.")
    if detect.get("method"):
        parts.append(f"Detected via {detect['method']} on {detect.get('detected_at', 'unknown date')}.")
    if narrative:
        parts.append(narrative)
    if techniques:
        parts.append(f"MITRE ATT&CK techniques observed: {', '.join(techniques[:8])}.")
    text = " ".join(parts)
    if len(text) > 500:
        text = text[:497] + "..."
    return text


def _how_occurred(s1: dict) -> str:
    detect = s1.get("detect") or {}
    timeline = s1.get("timeline") or []
    parts: list[str] = []
    if detect.get("method"):
        parts.append(f"Detection: {detect['method']}.")
    if timeline:
        first = timeline[0]
        parts.append(f"First observed: {first.get('event','')} at {first.get('ts','')}.")
    return " ".join(parts) or "Details under investigation."


def _contain_actions(s1: dict) -> str:
    contain = s1.get("contain") or {}
    actions = contain.get("actions") or []
    if not actions:
        return "Containment actions in progress; details to be supplied at human review."
    return "; ".join(str(a)[:200] for a in actions)


def _planned_actions(s7: dict) -> str:
    p1_actions = [a for a in (s7.get("actions") or []) if a.get("priority") == "P1"]
    if not p1_actions:
        return "Corrective actions under development."
    titles = [a.get("title", "") for a in p1_actions[:5]]
    return "; ".join(titles)


def _recommendations_to_individuals(affected_data: dict) -> str:
    classes = set(affected_data.get("classes") or [])
    if "credentials" in classes:
        return ("Affected individuals should change their passwords and enable "
                "multi-factor authentication where available.")
    if "credit_card" in classes:
        return ("Affected individuals should monitor their credit card statements "
                "and contact their issuer to flag suspicious activity.")
    if "customer_pii" in classes or "personal_information" in classes:
        return ("Affected individuals should remain alert to identity theft attempts "
                "and consider placing a credit ban with credit reporting bureaus.")
    return "Recommendations to be developed during human review."


def _evidence_summary(s3: dict) -> str:
    summary = s3.get("summary") or {}
    fc = summary.get("failed_control_count", 0)
    fws = summary.get("frameworks_with_failures") or []
    if fc == 0:
        return "Supporting control failure evidence available in JanuSec postmortem."
    return (f"{fc} control failures across frameworks: {', '.join(fws)}. "
            f"Full register with evidence row references in JanuSec postmortem.")


_NDB_REQUIRED = {
    "entity_name", "abn",
    "contact_person_name", "contact_person_email",
    "date_aware_of_breach", "kinds_of_information_involved",
    "approximate_individuals_affected", "description_of_breach",
}


def _ndb_review_checklist() -> list[str]:
    return [
        "Verify entity_name and ABN match the correct legal entity",
        "Confirm date_aware_of_breach is the actual discovery date as understood by the customer's legal team — the NDB clock starts when the customer entity becomes aware",
        "Review approximate_individuals_affected — platform estimate may need refinement",
        "Review description_of_breach for legal accuracy before submission",
        "Confirm 'individuals_at_risk_of_serious_harm' assessment is correct (this is a customer legal call, not a platform call)",
        "Confirm recommendations_to_individuals are appropriate and not over-promising",
        "Attach evidence documentation if required by OAIC",
        "Confirm submission is being made by an authorised person under the entity's privacy compliance program",
    ]


__all__ = ["prefill"]
