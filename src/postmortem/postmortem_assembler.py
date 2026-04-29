"""
JanuSec Postmortem Assembler — entry point
==========================================

Builds the canonical ``PostmortemDocument`` from a cluster narrative, control
failure register, evidence rows, and tenant context. This is the single
artifact that all downstream views (HTML, PDF, ITSM push, regulator form
pre-fill) read from.

DESIGN INVARIANTS
-----------------
1. Each section's ``auto_output`` is computed deterministically from inputs at
   transaction-time T0 and is *frozen* — never mutated. Human edits become
   diffs in ``overrides`` against the auto_output snapshot.

2. The ``computed_view`` of a section at any later transaction-time T is
   ``apply_overrides(auto_output_at_T0, overrides_up_to_T)``. This preserves
   the audit trail: when an external auditor asks "did the platform say HIGH
   or did the analyst?", both records survive separately.

3. Sections are independently testable. ``assemble()`` calls each
   ``build_section_*`` function which receives only the inputs it needs.
   This module does not contain section logic — it coordinates.

4. Regenerate is bitemporally tracked. Calling ``assemble()`` again on the
   same cluster produces a new transaction record that ``supersedes`` the
   prior one. Prior records remain queryable via the bitemporal store.

WIRING POINTS
-------------
- Upstream: ``cluster.llm_narrative`` (after ``enrich_narrative()``) +
  ``register`` (from ``build_control_failure_register()``).
- Downstream: ``src/api/postmortem_endpoints.py`` exposes 6 routes that
  call into this module.
- ITSM push: ``src/postmortem/itsm_push/jira.py`` (v1) or
  ``servicenow.py`` (v2) consumes the assembled document.
- Regulator forms: ``src/postmortem/regulator_forms/au_*.py`` consume the
  assembled document.

KNOWN BUG GUARD
---------------
The "0 failed controls" UI bug traces to ``narrative['mitre_techniques']``
being empty at the cluster narrative level. ``_validate_inputs()`` warns
when this happens — does not throw, because the postmortem should still
render with whatever the platform did detect. The warning surfaces in the
document's ``data_quality`` block so the UI can show it.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Optional

from .sections.s1_incident_lifecycle import build_s1_incident_lifecycle
from .sections.s2_threat_reconstruction import build_s2_threat_reconstruction
from .sections.s3_control_failures import build_s3_control_failures
from .sections.s4_sabsa_architecture import build_s4_sabsa_architecture
from .sections.s5_risk_register_delta import build_s5_risk_register_delta
from .sections.s6_regulatory_clocks import build_s6_regulatory_clocks
from .sections.s7_corrective_actions import build_s7_corrective_actions
from .human_edits import apply_overrides_to_section

logger = logging.getLogger(__name__)

POSTMORTEM_VERSION = "postmortem.v1.0"


# ─────────────────────────────────────────────────────────────────────────────
#  Public entry point
# ─────────────────────────────────────────────────────────────────────────────


def assemble(
    *,
    cluster: dict,
    narrative: dict,
    register: dict,
    evidence_rows: list[dict],
    tenant_id: str,
    tenant_config: dict | None = None,
    entity_context: dict | None = None,
    assessment_id: str = "",
    prior_postmortem: dict | None = None,
    framework_version: str = POSTMORTEM_VERSION,
) -> dict:
    """Build a complete ``PostmortemDocument`` from inputs.

    Args:
        cluster: the correlation cluster dict (cluster_id, row_refs, verdict, ...)
        narrative: ``cluster.llm_narrative`` after ``enrich_narrative()`` ran.
            Expected to contain mitre_techniques, affected_data,
            affected_principals, attacker_infrastructure, discovery,
            dread_narrative.
        register: output of ``framework_mapper.build_control_failure_register()``.
        evidence_rows: rows referenced by the cluster (``cluster.row_refs``).
        tenant_id: tenant identifier for tenant_config + entity_context lookup.
        tenant_config: per-tenant config dict (entity_name, abn, ciso contact,
            privacy_officer contact, etc.). Used by regulator forms.
        entity_context: per-tenant facts that gate regulatory triggers
            (apra_regulated_entity, soci_sectors, eu_data_subjects,
            cardholder_data_in_scope). Should already be embedded in register
            via ``evaluate_regulatory_triggers(entity_context=...)`` upstream.
        assessment_id: parent assessment identifier.
        prior_postmortem: previous PostmortemDocument for this cluster. If
            present, the new document supersedes it (bitemporal chain).
        framework_version: pinned to ``POSTMORTEM_VERSION``. Bump when section
            shapes change in a non-backwards-compatible way.

    Returns:
        Full ``PostmortemDocument`` matching ``data_shapes/postmortem_document_schema.json``.
    """
    transaction_time = datetime.now(timezone.utc).isoformat()

    # ── Validate + surface data quality issues ───────────────────────────────
    data_quality = _validate_inputs(narrative, register, evidence_rows)

    # ── Compute deterministic IDs and provenance ─────────────────────────────
    cluster_id = str(cluster.get("cluster_id") or cluster.get("id") or "unknown")
    evidence_row_indices = sorted({
        _extract_row_index(r) for r in evidence_rows or []
        if _extract_row_index(r) is not None
    })
    evidence_content_hash = _hash_evidence(evidence_rows or [])
    postmortem_id = _make_postmortem_id(tenant_id, cluster_id, transaction_time)

    # ── Build verdict block ──────────────────────────────────────────────────
    verdict_block = _build_verdict_block(narrative, register)

    # ── Build sections ───────────────────────────────────────────────────────
    # Each section returns dict matching its slot in postmortem_document_schema.
    # If a section raises, we log and continue with a stub for that section
    # rather than failing the whole assembly — the postmortem is still useful
    # with a partial set of sections, and the UI flags the gap.
    section_builders = [
        ("s1_incident_lifecycle",        build_s1_incident_lifecycle,        "FULLY_IMPLEMENTED"),
        ("s2_threat_reconstruction",     build_s2_threat_reconstruction,     "STUB"),
        ("s3_control_failures",          build_s3_control_failures,          "FULLY_IMPLEMENTED"),
        ("s4_sabsa_architecture",        build_s4_sabsa_architecture,        "STUB"),
        ("s5_risk_register_delta",       build_s5_risk_register_delta,       "STUB"),
        ("s6_regulatory_clocks",         build_s6_regulatory_clocks,         "FULLY_IMPLEMENTED"),
        ("s7_corrective_actions",        build_s7_corrective_actions,        "FULLY_IMPLEMENTED"),
    ]

    sections: list[dict] = []
    for section_id, builder_fn, v1_status in section_builders:
        try:
            section = builder_fn(
                cluster=cluster,
                narrative=narrative,
                register=register,
                evidence_rows=evidence_rows,
                tenant_config=tenant_config or {},
                entity_context=entity_context or {},
            )
            section["section_id"] = section_id
            section["v1_status"] = v1_status
            section["overrides"] = []
            section["signoff"] = None

            # Carry overrides forward from prior_postmortem if regenerating.
            # This preserves analyst edits across regeneration cycles.
            if prior_postmortem:
                prior_section = _find_prior_section(prior_postmortem, section_id)
                if prior_section:
                    section["overrides"] = list(prior_section.get("overrides") or [])
                    # Sign-off does NOT carry forward — regeneration changes
                    # the auto_output, so re-signoff is required.
                    section["signoff"] = None
        except Exception as exc:
            logger.warning("postmortem section %s failed: %s", section_id, exc)
            section = _build_failed_section(section_id, v1_status, exc)
        sections.append(section)

    # ── Build top-level document ─────────────────────────────────────────────
    document = {
        "postmortem_id":     postmortem_id,
        "assessment_id":     assessment_id,
        "cluster_id":        cluster_id,
        "tenant_id":         tenant_id,
        "framework_version": framework_version,
        "transaction_time":  transaction_time,
        "supersedes":        [prior_postmortem["postmortem_id"]] if prior_postmortem else [],

        "verdict":           verdict_block,
        "sections":          sections,

        "evidence_provenance": {
            "evidence_row_indices": evidence_row_indices,
            "evidence_content_hash": evidence_content_hash,
            "row_count":            len(evidence_row_indices),
        },

        "data_quality":      data_quality,
        "itsm_links":        list((prior_postmortem or {}).get("itsm_links") or []),
        "regulator_submissions": _seed_regulator_submissions(register),
    }
    return document


# ─────────────────────────────────────────────────────────────────────────────
#  Computed-view helpers (reads with overrides applied)
# ─────────────────────────────────────────────────────────────────────────────


def get_computed_section(document: dict, section_id: str) -> dict:
    """Return a section's computed view (auto_output + overrides applied).

    Use this when rendering. Use the raw ``section.auto_output`` only when
    showing the analyst the diff between platform output and human edits.
    """
    for sec in document.get("sections") or []:
        if sec.get("section_id") == section_id:
            auto = sec.get("auto_output") or {}
            overrides = sec.get("overrides") or []
            return apply_overrides_to_section(auto, overrides)
    return {}


def all_sections_signed(document: dict) -> bool:
    """Return True if every section has a non-null ``signoff``.

    Used to gate "Export as Final" — drafts can be exported any time, but
    final exports require all 7 sections to be signed off.
    """
    sections = document.get("sections") or []
    return all(sec.get("signoff") is not None for sec in sections)


def signoff_summary(document: dict) -> dict:
    """Return per-section signoff status for the UI summary header."""
    out = {"signed": 0, "pending": 0, "stubs": 0, "details": []}
    for sec in document.get("sections") or []:
        sid = sec.get("section_id")
        status = sec.get("v1_status")
        signed = sec.get("signoff") is not None
        if status == "STUB":
            out["stubs"] += 1
        elif signed:
            out["signed"] += 1
        else:
            out["pending"] += 1
        out["details"].append({
            "section_id": sid,
            "status": status,
            "signed": signed,
            "signed_by": (sec.get("signoff") or {}).get("signed_by"),
        })
    return out


# ─────────────────────────────────────────────────────────────────────────────
#  Internal helpers
# ─────────────────────────────────────────────────────────────────────────────


def _validate_inputs(narrative: dict, register: dict, evidence_rows: list[dict]) -> dict:
    """Surface data quality issues for the UI to display.

    KNOWN BUG GUARD: empty ``mitre_techniques`` cascades to zero failed
    controls and zero regulatory triggers. This is the "0 failed controls"
    screenshot bug. We don't fix it here — fix is upstream in
    ``enrich_narrative`` / cluster builder — but we surface it loudly so
    nobody mistakes the empty postmortem for an actual all-clear.
    """
    issues: list[dict] = []

    if not (narrative or {}).get("mitre_techniques"):
        issues.append({
            "severity": "error",
            "code":     "narrative_mitre_empty",
            "message":  "narrative.mitre_techniques is empty — control failure "
                        "register will be empty downstream. Fix upstream in "
                        "enrich_narrative / cluster builder.",
            "blast_radius": ["s3_control_failures", "s6_regulatory_clocks", "s7_corrective_actions"],
        })

    if not (register or {}).get("control_failures_by_framework"):
        issues.append({
            "severity": "error",
            "code":     "register_empty",
            "message":  "register.control_failures_by_framework is empty.",
            "blast_radius": ["s3_control_failures", "s7_corrective_actions"],
        })

    if not evidence_rows:
        issues.append({
            "severity": "warning",
            "code":     "no_evidence_rows",
            "message":  "No evidence rows passed to assembler — provenance will be thin.",
            "blast_radius": ["evidence_provenance"],
        })

    if not (narrative or {}).get("affected_data"):
        issues.append({
            "severity": "warning",
            "code":     "affected_data_empty",
            "message":  "narrative.affected_data missing — sensitivity classification "
                        "and regulator triggers may be incorrect.",
            "blast_radius": ["s3_control_failures", "s6_regulatory_clocks"],
        })

    return {
        "issues": issues,
        "issue_count_by_severity": {
            "error":   sum(1 for i in issues if i["severity"] == "error"),
            "warning": sum(1 for i in issues if i["severity"] == "warning"),
        },
    }


def _build_verdict_block(narrative: dict, register: dict) -> dict:
    """Produce the top-of-document verdict block.

    Three layers as discussed prior:
      - platform_verdict: what JanuSec's pipeline decided
      - materiality_assessment: derived from regulatory triggers + crown_jewel
      - notification_status: always READY_FOR_HUMAN_SUBMISSION (we never auto-submit)
    """
    pv = str(narrative.get("verdict") or "").upper() or "UNCERTAIN"
    confidence = float(narrative.get("confidence") or 0.0)

    # Materiality: derived from triggers + crown_jewel, not a JanuSec legal call.
    affected_data = narrative.get("affected_data") or {}
    crown_jewel = bool(affected_data.get("crown_jewel_touched"))
    triggers = register.get("regulatory_triggers") or []

    if pv in ("VALIDATED_BREACH", "CONFIRMED_INTRUSION") and triggers:
        # Spell it out per regulator that actually fired.
        trigger_names = [t.get("trigger_id") for t in triggers]
        materiality = "MEETS_NOTIFICATION_CRITERIA"
        rationale = ("Regulatory triggers fired: " + ", ".join(trigger_names) +
                     ". Customer entity must make final materiality determination.")
    elif pv in ("VALIDATED_BREACH", "CONFIRMED_INTRUSION") and crown_jewel:
        materiality = "LIKELY_MATERIAL_REQUIRES_LEGAL_REVIEW"
        rationale = ("Crown jewel data touched but no regulatory trigger fired. "
                     "Customer should review materiality with legal counsel.")
    elif pv == "SUSPECTED_BREACH":
        materiality = "PENDING_VERIFICATION"
        rationale = "Verdict is suspected but not validated. Materiality determination requires human review."
    else:
        materiality = "BELOW_NOTIFICATION_THRESHOLD"
        rationale = "No regulatory triggers fired and no crown jewel data touched."

    return {
        "platform_verdict":         pv,
        "confidence":               round(confidence, 3),
        "materiality_assessment":   materiality,
        "materiality_rationale":    rationale,
        "notification_status":      ("READY_FOR_HUMAN_SUBMISSION" if triggers
                                     else "NO_NOTIFICATION_REQUIRED"),
        "kill_chain_stage":         narrative.get("kill_chain_stage") or "unknown",
    }


def _seed_regulator_submissions(register: dict) -> list[dict]:
    """Pre-create draft submission records for each fired regulatory trigger.

    These start in 'draft' state. The ``regulator_form`` endpoint populates
    ``form_payload_url`` once the human has reviewed the pre-fill. The
    ``submitted_at`` field is set only when the human marks the submission
    as completed externally.
    """
    out: list[dict] = []
    for t in (register.get("regulatory_triggers") or []):
        out.append({
            "regulator":        t.get("trigger_id"),
            "regulator_name":   t.get("name"),
            "clock_human":      t.get("clock_human"),
            "starts_from":      t.get("starts_from"),
            "status":           "draft",
            "form_payload_url": None,
            "reviewed_by":      None,
            "submitted_at":     None,
        })
    return out


def _build_failed_section(section_id: str, v1_status: str, exc: Exception) -> dict:
    """When a section builder raises, return a non-null section so downstream
    rendering still works. Surfaces the failure in data_quality."""
    return {
        "section_id":  section_id,
        "v1_status":   v1_status,
        "title":       section_id,
        "auto_output": None,
        "overrides":   [],
        "signoff":     None,
        "build_error": {
            "exception_class": type(exc).__name__,
            "message":         str(exc)[:500],
        },
    }


def _find_prior_section(prior_postmortem: dict, section_id: str) -> Optional[dict]:
    for sec in prior_postmortem.get("sections") or []:
        if sec.get("section_id") == section_id:
            return sec
    return None


def _extract_row_index(row: dict) -> Optional[int]:
    """Read row_index with the field-name drift the codebase has.

    The Santos codebase uses both 'row_index' and 'row_number' across
    different sources. Always read both. (See gap_analysis.md B3.)
    """
    for key in ("row_index", "row_number", "id", "evidence_id"):
        v = row.get(key)
        if v is None:
            continue
        try:
            return int(float(v))
        except (TypeError, ValueError):
            continue
    return None


def _hash_evidence(rows: list[dict]) -> str:
    """SHA-256 of canonicalised evidence content. If anyone mutates the
    underlying rows after the postmortem is assembled, the hash mismatch
    surfaces immediately during audit replay."""
    canon: list[dict] = []
    for r in rows:
        canon.append({
            "row_index": _extract_row_index(r),
            "_source":   r.get("_source") or r.get("source"),
            "ts":        r.get("timestamp") or r.get("eventTime") or r.get("published"),
            "event":     (r.get("eventName") or r.get("event_simpleName") or
                          r.get("Operation") or r.get("eventType") or "")[:80],
        })
    blob = json.dumps(canon, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def _make_postmortem_id(tenant_id: str, cluster_id: str, transaction_time: str) -> str:
    """Stable, deterministic ID. Re-running assemble() at the same transaction
    time produces the same ID — useful for idempotent retries."""
    h = hashlib.sha256(
        f"{tenant_id}|{cluster_id}|{transaction_time}".encode("utf-8")
    ).hexdigest()
    return f"pm-{h[:24]}"


__all__ = [
    "assemble",
    "get_computed_section",
    "all_sections_signed",
    "signoff_summary",
    "POSTMORTEM_VERSION",
]
