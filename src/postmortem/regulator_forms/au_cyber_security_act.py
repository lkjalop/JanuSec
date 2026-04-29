"""
Cyber Security Act 2024 (Cth) — Ransomware Payment Reporting Pre-fill
======================================================================

Schedule 1 — Ransomware Payment Reporting.

CLOCK
-----
72 hours from making (or arranging to make) the ransomware payment, OR from
becoming aware that a payment was made on the entity's behalf.

APPLICABILITY GATE
------------------
Only applicable if a ransomware payment was actually made or arranged.
This module checks ``tenant_config['_ransomware_payment_made']``. If false
or unset, returns ``applicable: false``.

NEVER AUTO-SUBMITS
------------------
Submitted to the designated Commonwealth body (currently ASD/Home Affairs).
Has sanctions implications (OFAC, DFAT) — must be reviewed by legal counsel
before filing.
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

    # Applicability gate — only file if a ransomware payment was made.
    payment_made = bool(tenant_config.get("_ransomware_payment_made", False))
    if not payment_made:
        return {
            "regulator":                "au_csa_ransomware",
            "regulator_name":           "Australian Signals Directorate — Designated Commonwealth Body",
            "applicable":               False,
            "applicability_rationale":  "No ransomware payment made or arranged. This form is only required if a payment occurred.",
            "human_review_required":    True,
            "auto_submit_allowed":      False,
            "fields":                   {},
            "field_provenance":         {},
            "human_review_checklist": [
                "If a ransomware payment is being considered, consult legal counsel BEFORE making the payment — sanctions implications (OFAC, DFAT)",
                "If a payment has been made or arranged, return to this form within 72 hours and update _ransomware_payment_made flag",
            ],
        }

    ciso = (tenant_config.get("ciso") or {})

    # Payment metadata is supplied by the customer at the time of payment;
    # we never derive or compute payment amounts from telemetry.
    payment_meta = tenant_config.get("_ransomware_payment_meta") or {}

    fields: dict[str, Any] = {
        # Entity identification
        "reporting_entity_name":     tenant_config.get("entity_name"),
        "reporting_entity_abn":      tenant_config.get("abn"),

        # Contact (CISO + legal)
        "contact_name":              ciso.get("name"),
        "contact_email":             ciso.get("email"),
        "contact_phone":             ciso.get("phone"),

        # Payment details (from customer-supplied metadata)
        "date_payment_made":         payment_meta.get("date_payment_made"),
        "payment_amount":            payment_meta.get("payment_amount"),
        "payment_currency":          payment_meta.get("payment_currency"),
        "payment_method":            payment_meta.get("payment_method"),
        "recipient_wallet_address":  payment_meta.get("recipient_wallet_address"),
        "payment_intermediary":      payment_meta.get("payment_intermediary"),

        # Threat / damage context
        "ransomware_variant":        s2.get("threat_actor_profile") or "unknown",
        "threat_actor_attribution":  _attacker_prose(attacker_infra),
        "systems_encrypted":         affected_principals.get("hosts") or [],
        "data_exfiltrated_prior_to_payment": affected_data.get("classes") or [],

        # Decision context
        "reason_for_payment":        payment_meta.get("reason_for_payment"),
        "alternatives_considered":   payment_meta.get("alternatives_considered"),
        "board_approval_obtained":   payment_meta.get("board_approval_obtained"),
        "legal_counsel_consulted":   payment_meta.get("legal_counsel_consulted"),

        # Law enforcement
        "law_enforcement_notified_afp":  payment_meta.get("afp_notified", False),
        "law_enforcement_reference":     payment_meta.get("afp_reference"),
    }

    field_provenance = {
        "ransomware_variant":        ["section_s2.auto_output.threat_actor_profile"],
        "threat_actor_attribution":  ["narrative.attacker_infrastructure"],
        "systems_encrypted":         ["narrative.affected_principals.hosts"],
        "data_exfiltrated_prior_to_payment": ["narrative.affected_data.classes"],
        # Payment metadata fields are tenant-supplied, not derived.
    }

    return {
        "regulator":                "au_csa_ransomware",
        "regulator_name":           "Australian Signals Directorate — Designated Commonwealth Body",
        "form_version":             "au_csa_ransomware_reporting_2024",
        "notification_scheme":      "Cyber Security Act 2024 (Cth), Schedule 1",
        "applicable":               True,
        "clock_seconds":            259200,    # 72h
        "clock_human":              "72h",
        "clock_note":               "72h from making or arranging to make the ransomware payment, or from becoming aware that a payment has been made on the entity's behalf",
        "human_review_required":    True,
        "auto_submit_allowed":      False,
        "submission_method":        "manual_form_with_review",
        "fields":                   fields,
        "field_provenance":         field_provenance,
        "human_review_checklist":   _csa_review_checklist(),
        "missing_required_fields":  [k for k, v in fields.items() if v in (None, "", []) and k in _CSA_REQUIRED],
    }


# ─────────────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _attacker_prose(infra: dict) -> str:
    asns = infra.get("asns") or []
    countries = infra.get("countries") or []
    parts: list[str] = []
    if countries:
        parts.append(f"Source countries: {', '.join(countries[:3])}.")
    if asns:
        parts.append(f"Source ASNs: {', '.join(asns[:5])}.")
    return " ".join(parts) or "Attribution under analysis."


_CSA_REQUIRED = {
    "reporting_entity_name", "reporting_entity_abn",
    "contact_name", "contact_email",
    "date_payment_made", "payment_amount",
}


def _csa_review_checklist() -> list[str]:
    return [
        "STOP: Confirm a ransomware payment was actually made or arranged before filing this form",
        "Verify payment amount, currency, and recipient wallet address with the finance team",
        "Consult legal counsel — ransomware payments may have sanctions implications (OFAC, DFAT)",
        "Confirm AFP has been notified or has formally declined notification",
        "Do not include negotiation details, decryption keys, or threat-actor demands in this form",
        "This report is SEPARATE FROM and IN ADDITION TO any OAIC NDB, APRA CPS 234, or SOCI Act reports",
        "Submission must be by an authorised officer of the entity",
    ]


__all__ = ["prefill"]
