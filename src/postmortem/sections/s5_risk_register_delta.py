"""
Section 5 — Risk Register Delta
================================

v1 status: STUB

In v2 this section will produce per-cluster risk register entries with
realized loss data linked to bitemporal trace. Each control failure
becomes a risk register entry with first_observed (bitemporal valid_time),
inherent + residual likelihood/impact, and realized_loss_to_date summed
across all incidents that have implicated this risk.

In v1 we emit a minimal view of new-risk candidates derived from the
control failure register, without the bitemporal join. The customer's
own GRC platform owns the authoritative risk register.

CONTRACT
--------
Even as a stub we emit ``new_risk_candidates`` because the Jira ITSM push
module reads this to create child tasks of type "RISK_REGISTER_REVIEW".
"""
from __future__ import annotations


def build_s5_risk_register_delta(
    *,
    cluster: dict,
    narrative: dict,
    register: dict,
    evidence_rows: list[dict],
    tenant_config: dict,
    entity_context: dict,
) -> dict:
    """Stub: derive new-risk candidates from control failures."""
    cf = (register or {}).get("control_failures_by_framework") or {}
    candidates: list[dict] = []

    # Group failed controls by triggering technique. Each technique becomes
    # a risk register candidate. Customer's GRC team confirms or merges.
    by_technique: dict[str, list[dict]] = {}
    for fw, recs in cf.items():
        if fw == "unmapped_techniques":
            continue
        for r in recs:
            for tech in (r.get("triggered_by") or []):
                by_technique.setdefault(str(tech), []).append({
                    "framework":  fw,
                    "control_id": r.get("control_id"),
                    "severity":   r.get("severity"),
                })

    affected = narrative.get("affected_data") or {}

    for tech, control_refs in by_technique.items():
        # Severity = highest of any control failure under this technique
        sevs = [_sev_rank(c["severity"]) for c in control_refs]
        max_sev = max(sevs) if sevs else 3
        candidates.append({
            "candidate_risk_id":     f"risk_candidate_{tech}",
            "technique":             tech,
            "title":                 f"Recurrence of {tech} attack pattern",
            "description":           f"Observed via {len(control_refs)} control failure(s) "
                                     f"in this incident.",
            "control_failures":      control_refs,
            "severity":              _rank_to_sev(max_sev),
            "affected_data_classes": list(affected.get("classes") or []),
            "review_action":         "Customer GRC team to confirm whether this is a new risk "
                                     "or a realised existing risk from the register.",
        })

    auto_output = {
        "new_risk_candidates":   candidates,
        "elevated_risks":        [],   # populated in v2 with bitemporal join
        "realised_loss_data":    None, # populated in v2
        "v1_note":                "Full risk register delta with bitemporal link to prior "
                                  "incidents arrives in v2. The candidates above are derived "
                                  "from this incident's control failures and should be reconciled "
                                  "against the customer's existing risk register.",
    }
    return {
        "title": "Risk Register Delta",
        "auto_output": auto_output,
    }


def _sev_rank(s: str) -> int:
    return {"critical": 0, "high": 1, "moderate": 2, "low": 3}.get((s or "low").lower(), 3)


def _rank_to_sev(rank: int) -> str:
    return ["critical", "high", "moderate", "low"][min(max(rank, 0), 3)]
