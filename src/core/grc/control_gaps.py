"""Summarize candidate control concerns; a technique citation is not a failed test."""
from __future__ import annotations

from typing import Any

# Total control counts per framework (honest denominators for the gap summary).
FRAMEWORK_TOTALS: dict[str, int] = {
    "iso27001": 93,      # ISO/IEC 27001:2022 Annex A
    "soc2": 33,          # SOC 2 Common Criteria points of focus (approx.)
    "iso42001": 38,      # ISO/IEC 42001:2023 Annex A
    "nist_csf": 108,     # NIST CSF 2.0 subcategories (approx.)
    "nist_800_53": 20,   # (families touched — coarse)
}

# Human-readable control names for the controls we map (auditors read names, not IDs).
_CONTROL_NAMES: dict[str, dict[str, str]] = {
    "iso27001": {
        "A.5.14": "Information transfer", "A.5.15": "Access control",
        "A.5.16": "Identity management", "A.5.17": "Authentication information",
        "A.5.18": "Access rights", "A.5.24": "Incident management planning",
        "A.5.26": "Response to incidents", "A.8.2": "Privileged access rights",
        "A.8.3": "Information access restriction", "A.8.5": "Secure authentication",
        "A.8.7": "Protection against malware", "A.8.9": "Configuration management",
        "A.8.12": "Data leakage prevention", "A.8.13": "Information backup",
        "A.8.16": "Monitoring activities", "A.8.20": "Networks security",
        "A.8.22": "Segregation of networks", "A.8.23": "Web filtering",
        "A.8.24": "Use of cryptography",
    },
    "soc2": {
        "CC6.1": "Logical access — provisioning & authentication",
        "CC6.2": "Registration & authorization of users",
        "CC6.3": "Role-based access & least privilege",
        "CC6.6": "Boundary protection",
        "CC6.7": "Restriction of data movement",
        "CC7.2": "Detection & monitoring of anomalies",
        "CC7.3": "Evaluation of security events",
    },
    "iso42001": {
        "A.6.2.4": "AI system operation & monitoring",
        "A.9.2": "AI system use & accountability",
    },
}

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "trace": 0}


def _worse(a: str, b: str) -> str:
    return a if _SEV_RANK.get(a, 0) >= _SEV_RANK.get(b, 0) else b


def build_control_gaps(audit_pack: dict) -> dict[str, Any]:
    """Grade each control touched by a Nonconformity. Returns
    {gaps: {framework: {control: record}}, summary: {framework: {...}}}."""
    gaps: dict[str, dict[str, dict]] = {}
    for nc in audit_pack.get("nonconformities", []):
        dread_level = str(nc.get("dread_level") or "low")
        dread_score = float(nc.get("dread_score") or 0.0)
        for fw, controls in (nc.get("control_refs") or {}).items():
            for ctrl in controls:
                rec = gaps.setdefault(fw, {}).setdefault(ctrl, {
                    "control": ctrl, "framework": fw,
                    "name": _CONTROL_NAMES.get(fw, {}).get(ctrl, ""),
                    "status": "candidate", "nc_ids": [],
                    "worst_dread": 0.0, "severity": "low", "finding_count": 0,
                })
                if nc.get("nc_id") not in rec["nc_ids"]:
                    rec["nc_ids"].append(nc.get("nc_id"))
                    rec["finding_count"] += 1
                if dread_score > rec["worst_dread"]:
                    rec["worst_dread"] = round(dread_score, 2)
                rec["severity"] = _worse(rec["severity"], dread_level)

    summary: dict[str, dict] = {}
    for fw, ctrls in gaps.items():
        total = FRAMEWORK_TOTALS.get(fw)
        failing = len(ctrls)
        worst = "low"
        for rec in ctrls.values():
            worst = _worse(worst, rec["severity"])
        summary[fw] = {
            "controls_failing": 0,
            "controls_requiring_review": failing,
            "total_controls": total,
            "gap_pct": None,
            "candidate_reference_pct": round(failing / total * 100, 1) if total else None,
            "worst_severity": worst,
        }
    return {"gaps": gaps, "summary": summary}
