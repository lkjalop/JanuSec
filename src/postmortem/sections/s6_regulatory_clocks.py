"""
Section 6 — Regulatory Notification Clocks
==========================================

v1 status: FULLY_IMPLEMENTED

Reads ``register['regulatory_triggers']`` produced by
``framework_mapper.evaluate_regulatory_triggers()`` and projects each trigger
into a notification clock entry with deadline math, status, and link to the
pre-fill regulator form.

NEVER auto-submits. ``submission_status`` is always
"READY_FOR_HUMAN_SUBMISSION" or a downstream state set by the human-driven
submission flow ("under_legal_review", "submitted", "withdrawn").

INPUTS
------
- register['regulatory_triggers']
- register['tightest_clock_seconds']

OUTPUTS
-------
- summary: trigger count, tightest deadline, soonest hours_remaining
- triggers: list of regulatory clock entries with deadline + form links
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger(__name__)


def build_s6_regulatory_clocks(
    *,
    cluster: dict,
    narrative: dict,
    register: dict,
    evidence_rows: list[dict],
    tenant_config: dict,
    entity_context: dict,
) -> dict:
    triggers = list((register or {}).get("regulatory_triggers") or [])
    now_utc = datetime.now(timezone.utc)

    enriched_triggers = [_enrich_trigger(t, now_utc) for t in triggers]

    summary = _build_summary(enriched_triggers)

    auto_output = {
        "summary":   summary,
        "triggers":  enriched_triggers,
        "human_submit_only_notice": (
            "JanuSec NEVER auto-submits to a regulator. All notifications "
            "below are pre-fills only. The customer's authorised person must "
            "review each pre-filled form, make the materiality determination, "
            "and submit through the regulator's official channel. The platform "
            "records the submission timestamp once the human marks it complete."
        ),
    }

    return {
        "title": "Regulatory Notification Clocks",
        "auto_output": auto_output,
    }


def _enrich_trigger(trigger: dict, now_utc: datetime) -> dict:
    """Add deadline math and status to a raw trigger."""
    starts_from_iso = trigger.get("starts_from")
    clock_seconds = int(trigger.get("clock_seconds") or 0)
    deadline_iso = None
    hours_remaining: float | None = None
    overdue = False

    if starts_from_iso and clock_seconds > 0:
        try:
            sf = datetime.fromisoformat(starts_from_iso.replace("Z", "+00:00"))
            deadline_dt = sf + timedelta(seconds=clock_seconds)
            deadline_iso = deadline_dt.isoformat()
            delta = (deadline_dt - now_utc).total_seconds()
            hours_remaining = round(delta / 3600.0, 1)
            overdue = delta < 0
        except (ValueError, TypeError) as exc:
            logger.warning("s6: bad starts_from %s: %s", starts_from_iso, exc)

    return {
        "trigger_id":           trigger.get("trigger_id"),
        "name":                 trigger.get("name"),
        "jurisdiction":         trigger.get("jurisdiction"),
        "regulator":            trigger.get("regulator"),
        "clock_human":          trigger.get("clock_human"),
        "clock_seconds":        clock_seconds,
        "starts_from":          starts_from_iso,
        "deadline":             deadline_iso,
        "hours_remaining":      hours_remaining,
        "overdue":              overdue,
        "rationale":            trigger.get("rationale"),
        "severity_at_trigger":  trigger.get("severity_at_trigger"),
        "submission_status":    "READY_FOR_HUMAN_SUBMISSION",
        "form_module":          _form_module_for_trigger(trigger.get("trigger_id")),
        "form_payload_url":     None,   # set when /regulator-form endpoint runs
        "submitted_at":         None,
    }


def _form_module_for_trigger(trigger_id: str | None) -> str | None:
    """Map a trigger_id to the regulator_forms module that pre-fills it.

    These map to ``src/postmortem/regulator_forms/{module}.py``.
    """
    mapping = {
        "ndb_privacy_act":         "au_ndb",
        "apra_cps234":             "au_apra_cps234",
        "soci_act":                "au_soci",
        "cyber_security_act":      "au_cyber_security_act",
        "csa_ransomware":          "au_cyber_security_act",
    }
    return mapping.get(trigger_id) if trigger_id else None


def _build_summary(triggers: list[dict]) -> dict:
    if not triggers:
        return {
            "trigger_count":          0,
            "tightest_deadline":      None,
            "tightest_hours_left":    None,
            "any_overdue":            False,
            "regulators_to_notify":   [],
        }

    # Find the tightest live deadline.
    deadlines = [t for t in triggers if t.get("deadline")]
    deadlines.sort(key=lambda t: t.get("hours_remaining") or 99999.0)
    tightest = deadlines[0] if deadlines else None

    return {
        "trigger_count":        len(triggers),
        "tightest_deadline":    (tightest or {}).get("deadline"),
        "tightest_hours_left":  (tightest or {}).get("hours_remaining"),
        "tightest_trigger_id":  (tightest or {}).get("trigger_id"),
        "any_overdue":          any(t.get("overdue") for t in triggers),
        "regulators_to_notify": sorted({t.get("regulator") for t in triggers if t.get("regulator")}),
    }
