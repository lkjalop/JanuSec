"""
Section 3 — Control Failures by Framework (ISO 27001 + E8 + APRA + others)
==========================================================================

v1 status: FULLY_IMPLEMENTED

Lifts directly from ``register['control_failures_by_framework']`` produced by
``framework_mapper.build_control_failure_register()``. Adds:
  - Severity-ordered flat list (for the UI table)
  - Per-framework summary counts
  - SoA (Statement of Applicability) delta — which Annex A controls move from
    "implemented" to "failed_implementation_in_incident" status
  - Auditor-asks list — questions the external auditor will likely ask

INPUTS
------
- register['control_failures_by_framework'] (dict by framework key)
- register['failed_control_count']
- register['critical_control_count']
- narrative['mitre_techniques']  (for completeness check)

OUTPUTS
-------
- summary: counts and frameworks list
- by_framework: per-framework grouped failures
- flat_list: severity-sorted list for the UI table
- soa_delta: list of {control_id, prior_status, new_status, evidence_refs}
- auditor_asks: list of strings — questions to expect from the external auditor
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_SEV_ORDER = {"critical": 0, "high": 1, "moderate": 2, "low": 3}


def build_s3_control_failures(
    *,
    cluster: dict,
    narrative: dict,
    register: dict,
    evidence_rows: list[dict],
    tenant_config: dict,
    entity_context: dict,
) -> dict:
    cf = (register or {}).get("control_failures_by_framework") or {}
    failed_count = int((register or {}).get("failed_control_count") or 0)
    critical_count = int((register or {}).get("critical_control_count") or 0)

    by_framework = {fw: list(recs) for fw, recs in cf.items()
                    if fw != "unmapped_techniques"}
    frameworks_with_failures = sorted(
        fw for fw, recs in by_framework.items() if recs
    )

    flat_list = _flatten_and_sort(by_framework)
    soa_delta = _build_soa_delta(by_framework)
    auditor_asks = _build_auditor_asks(by_framework, narrative)
    unmapped = list(cf.get("unmapped_techniques") or [])

    auto_output = {
        "summary": {
            "failed_control_count":      failed_count,
            "critical_control_count":    critical_count,
            "frameworks_with_failures":  frameworks_with_failures,
            "framework_count":           len(frameworks_with_failures),
            "evidence_link_count":       int((register or {}).get("evidence_link_count") or 0),
            "unmapped_technique_count":  len(unmapped),
        },
        "by_framework":  by_framework,
        "flat_list":     flat_list,
        "soa_delta":     soa_delta,
        "auditor_asks":  auditor_asks,
        "unmapped_techniques": unmapped,
    }

    return {
        "title": "Control Failures by Framework",
        "auto_output": auto_output,
    }


def _flatten_and_sort(by_framework: dict) -> list[dict]:
    """Produce one flat severity-ordered list for the UI table."""
    flat: list[dict] = []
    for fw, recs in by_framework.items():
        for r in recs:
            flat.append({
                "framework":             fw,
                "control_id":            r.get("control_id", ""),
                "control_name":          r.get("control_name", ""),
                "failure_type":          r.get("failure_type", ""),
                "severity":              r.get("severity", "low"),
                "remediation_priority":  r.get("remediation_priority", "P3"),
                "triggered_by":          list(r.get("triggered_by") or []),
                "evidence_refs":         list(r.get("evidence_refs") or []),
            })
    flat.sort(key=lambda x: (
        _SEV_ORDER.get(x["severity"], 99),
        x["framework"],
        x["control_id"],
    ))
    return flat


def _build_soa_delta(by_framework: dict) -> list[dict]:
    """Statement of Applicability delta — only ISO 27001 Annex A controls.

    For each ISO failed control, produce an SoA delta record that the
    customer's GRC team can append to their SoA. We don't know the prior
    state (without integrating to their GRC), so we mark prior_status as
    'unknown' — the analyst confirms during sign-off.
    """
    out: list[dict] = []
    iso_failures = by_framework.get("iso27001") or []
    for r in iso_failures:
        out.append({
            "framework":      "iso27001",
            "control_id":     r.get("control_id"),
            "control_name":   r.get("control_name"),
            "prior_status":   "unknown",  # analyst confirms during signoff
            "new_status":     "failed_in_incident",
            "evidence_refs":  list(r.get("evidence_refs") or []),
            "review_action":  "Update SoA to reflect compensating control or "
                              "mark as not-applicable with rationale.",
        })
    return out


def _build_auditor_asks(by_framework: dict, narrative: dict) -> list[str]:
    """Generate the questions an external auditor (ISO 27001 LA, APRA, OAIC)
    is likely to ask given this control failure pattern.

    These prime the analyst to prepare evidence in advance of the audit
    walkthrough rather than scrambling during it.
    """
    asks: list[str] = []
    iso_failures = by_framework.get("iso27001") or []
    e8_failures = by_framework.get("essential_eight") or []
    apra_failures = by_framework.get("apra_cps234") or []

    iso_ids = {r.get("control_id") for r in iso_failures}
    if "A.5.15" in iso_ids or "A.5.16" in iso_ids:
        asks.append("Show the access review records for the 12 months "
                    "preceding the incident — frequency, attendees, exceptions.")
    if "A.5.17" in iso_ids:
        asks.append("Show the privileged access management policy and the "
                    "list of approved privileged accounts at the time of incident.")
    if "A.8.5" in iso_ids:
        asks.append("Show the MFA enforcement policy and any documented "
                    "exclusions in force at the time of incident.")
    if "A.8.22" in iso_ids:
        asks.append("Show the network segmentation diagram and the controls "
                    "that should have prevented lateral movement to the affected segment.")

    if e8_failures:
        asks.append("Provide the most recent Essential Eight maturity self-"
                    "assessment with the maturity level (ML1/ML2/ML3) per mitigation.")

    if apra_failures:
        asks.append("Provide the entity's CPS 234 internal audit report and "
                    "the dates of the last and next external audit of CPS 234 compliance.")
        asks.append("Provide evidence the Board was apprised of this incident "
                    "in accordance with CPS 234 paragraphs 13–14.")

    affected = narrative.get("affected_data") or {}
    if affected.get("crown_jewel_touched"):
        asks.append("Provide the data classification policy and the prior "
                    "classification record for the affected information assets.")

    discovery = narrative.get("discovery") or {}
    if discovery.get("source", "").lower().endswith("pentest") or \
       discovery.get("source", "").lower().endswith("external_pentest"):
        asks.append("The incident was discovered via external assessment, "
                    "not internal SOC. Show the prior 12 months of SOC alerts "
                    "for the affected systems and explain why this activity "
                    "did not trigger an internal detection.")

    if not asks:
        asks.append("Walk through the control failure register row by row "
                    "with corresponding evidence rows for each.")
    return asks
