"""Compliance control violation mapper.

Maps JanuSec factor_tags to regulatory and security-framework control
violations. Called in Stage 5k (assessment_worker) to populate
cluster["compliance_violations"] — a structured block consumed by:
  - Persona dispatch (compliance persona prompt injection)
  - Executive summary renderer
  - breach.js cluster detail panel

Frameworks covered:
  - NIST SP 800-53 rev5
  - ISO/IEC 27001:2022
  - CIS Controls v8
  - SOC 2 Trust Services Criteria (2017)
  - MITRE ATT&CK (technique IDs, used for cross-reference not mandate)

Adding a new factor_tag: add an entry to _CONTROL_VIOLATIONS below.
The key is the exact factor_tag string emitted by assessment_worker or
any detector. All framework fields are optional (empty list = not mapped).
"""
from __future__ import annotations

from typing import Dict, List, Any

# ─────────────────────────────────────────────────────────────────────────────
#  Master control violation table
# ─────────────────────────────────────────────────────────────────────────────

_CONTROL_VIOLATIONS: Dict[str, Dict[str, Any]] = {

    # ── IAM / Kerberos ───────────────────────────────────────────────────────
    "iam:as_rep_roasting": {
        "label": "AS-REP Roasting — pre-auth disabled",
        "nist_800_53": ["AC-3", "IA-5(1)", "SI-4"],
        "iso_27001":   ["A.9.4.1", "A.9.2.4", "A.9.4.3"],
        "cis_v8":      ["5.4", "6.1", "6.2"],
        "soc2_cc":     ["CC6.1", "CC6.6", "CC7.2"],
        "mitre":       ["T1558.004"],
        "severity":    "high",
    },
    "iam:kerberoasting": {
        "label": "Kerberoasting — RC4 TGS downgrade",
        "nist_800_53": ["AC-3", "IA-5(1)", "SI-4", "AU-12"],
        "iso_27001":   ["A.9.4.1", "A.9.2.4"],
        "cis_v8":      ["5.4", "6.1"],
        "soc2_cc":     ["CC6.1", "CC6.6"],
        "mitre":       ["T1558.003"],
        "severity":    "high",
    },
    "iam:golden_ticket": {
        "label": "Golden Ticket — forged Kerberos TGT",
        "nist_800_53": ["IA-2", "AC-3", "AU-9", "SI-7"],
        "iso_27001":   ["A.9.2.3", "A.9.4.2", "A.12.4.1"],
        "cis_v8":      ["5.4", "6.5", "8.2"],
        "soc2_cc":     ["CC6.1", "CC6.3", "CC7.3"],
        "mitre":       ["T1558.001"],
        "severity":    "critical",
    },
    "iam:kerberos_delegation_abuse": {
        "label": "Kerberos unconstrained delegation abuse",
        "nist_800_53": ["AC-3", "AC-6"],
        "iso_27001":   ["A.9.4.1"],
        "cis_v8":      ["5.4"],
        "soc2_cc":     ["CC6.3"],
        "mitre":       ["T1134.001"],
        "severity":    "high",
    },
    "iam:sid_history_injection": {
        "label": "SID History injection",
        "nist_800_53": ["AC-3", "AC-6", "CM-6"],
        "iso_27001":   ["A.9.2.3"],
        "cis_v8":      ["5.4", "5.6"],
        "soc2_cc":     ["CC6.3"],
        "mitre":       ["T1134.005"],
        "severity":    "critical",
    },
    "iam:security_support_provider_dll": {
        "label": "SSP DLL injected into LSASS — credential theft",
        "nist_800_53": ["SI-3", "SI-7", "AU-12"],
        "iso_27001":   ["A.12.2.1", "A.12.4.1"],
        "cis_v8":      ["10.5", "8.2"],
        "soc2_cc":     ["CC7.2", "CC7.3"],
        "mitre":       ["T1547.005"],
        "severity":    "critical",
    },
    "iam:authentication_package_modification": {
        "label": "Authentication package registry modification",
        "nist_800_53": ["CM-6", "CM-7", "SI-7"],
        "iso_27001":   ["A.12.5.1"],
        "cis_v8":      ["4.1", "10.5"],
        "soc2_cc":     ["CC7.1"],
        "mitre":       ["T1547.002"],
        "severity":    "high",
    },
    "iam:service_principal_credential_add": {
        "label": "Service principal credential added — persistence",
        "nist_800_53": ["IA-5", "AC-2", "CM-6", "AU-12"],
        "iso_27001":   ["A.9.2.1", "A.9.2.6", "A.9.4.2"],
        "cis_v8":      ["5.3", "5.4"],
        "soc2_cc":     ["CC6.1", "CC6.3"],
        "mitre":       ["T1098.001"],
        "severity":    "high",
    },

    # ── Cloud / OAuth / Azure AD ─────────────────────────────────────────────
    "iam:azure_device_code_phishing": {
        "label": "Device code phishing — OAuth token theft",
        "nist_800_53": ["IA-8", "SI-4", "AC-17"],
        "iso_27001":   ["A.9.1.2", "A.9.4.3"],
        "cis_v8":      ["16.5", "16.8"],
        "soc2_cc":     ["CC6.6", "CC6.7"],
        "mitre":       ["T1528"],
        "severity":    "high",
    },
    "iam:oauth_consent_grant_suspicious_app": {
        "label": "OAuth consent grant to unverified application",
        "nist_800_53": ["AC-3", "AC-6", "IA-8"],
        "iso_27001":   ["A.9.1.2", "A.14.1.2"],
        "cis_v8":      ["16.3", "16.5"],
        "soc2_cc":     ["CC6.1", "CC6.6"],
        "mitre":       ["T1528"],
        "severity":    "high",
    },
    "iam:azure_legacy_auth": {
        "label": "Legacy authentication protocol in use",
        "nist_800_53": ["IA-8", "SC-8"],
        "iso_27001":   ["A.9.4.3", "A.13.1.1"],
        "cis_v8":      ["16.3"],
        "soc2_cc":     ["CC6.6"],
        "mitre":       ["T1078.004"],
        "severity":    "medium",
    },
    "iam:conditional_access_bypass": {
        "label": "Conditional access policy bypassed",
        "nist_800_53": ["AC-17", "IA-3", "IA-8"],
        "iso_27001":   ["A.9.1.2", "A.9.4.3"],
        "cis_v8":      ["16.5", "16.8"],
        "soc2_cc":     ["CC6.6", "CC6.7"],
        "mitre":       ["T1078.004"],
        "severity":    "high",
    },
    "iam:azure_privileged_role_activation_unusual": {
        "label": "PIM privileged role activation — anomalous timing",
        "nist_800_53": ["AC-6", "AU-6", "SI-4"],
        "iso_27001":   ["A.9.2.3", "A.12.4.1"],
        "cis_v8":      ["5.4", "6.2"],
        "soc2_cc":     ["CC6.3", "CC7.2"],
        "mitre":       ["T1078.004"],
        "severity":    "medium",
    },
    "iam:entra_id_risky_sign_in": {
        "label": "Entra ID risky sign-in flagged by Identity Protection",
        "nist_800_53": ["IA-8", "SI-4", "AU-6"],
        "iso_27001":   ["A.9.1.2", "A.12.4.1"],
        "cis_v8":      ["16.6", "8.2"],
        "soc2_cc":     ["CC6.6", "CC7.2"],
        "mitre":       ["T1078.004"],
        "severity":    "medium",
    },

    # ── Recon / off-hours ────────────────────────────────────────────────────
    "recon:sustained_offhours_sequence": {
        "label": "Sustained off-hours AD recon sequence (Days 3-6 pattern)",
        "nist_800_53": ["AU-6", "SI-4(5)", "CM-7"],
        "iso_27001":   ["A.12.4.1", "A.12.6.1", "A.16.1.1"],
        "cis_v8":      ["8.2", "8.11", "17.4"],
        "soc2_cc":     ["CC7.2", "CC7.3"],
        "mitre":       ["T1087.002", "T1069.002", "T1018"],
        "severity":    "high",
    },

    # ── Exfiltration ─────────────────────────────────────────────────────────
    "exfil:cumulative_bytes_anomaly": {
        "label": "Cumulative data exfiltration — multi-day byte volume anomaly",
        "nist_800_53": ["AC-4", "SI-4", "SC-7", "AU-12"],
        "iso_27001":   ["A.13.2.1", "A.12.4.1", "A.13.1.1"],
        "cis_v8":      ["13.8", "8.2", "13.3"],
        "soc2_cc":     ["CC7.2", "CC6.7", "CC7.3"],
        "mitre":       ["T1048", "T1567", "T1041"],
        "severity":    "critical",
    },
    "exfil:cumulative_cloud_bytes_anomaly": {
        "label": "Cumulative cloud-destination exfiltration — sustained high bytes",
        "nist_800_53": ["AC-4", "SI-4", "SC-7"],
        "iso_27001":   ["A.13.2.1", "A.12.4.1"],
        "cis_v8":      ["13.8", "13.3"],
        "soc2_cc":     ["CC7.2", "CC6.7"],
        "mitre":       ["T1567", "T1048.002"],
        "severity":    "critical",
    },
    "data:large_extract": {
        "label": "Single large data extract exceeds EWMA baseline",
        "nist_800_53": ["AC-4", "SI-4", "AU-12"],
        "iso_27001":   ["A.13.2.1", "A.12.4.1"],
        "cis_v8":      ["13.8"],
        "soc2_cc":     ["CC7.2"],
        "mitre":       ["T1530", "T1048"],
        "severity":    "high",
    },

    # ── Network / SharePoint ─────────────────────────────────────────────────
    "network:sharepoint_subdomain_mismatch": {
        "label": "SharePoint lookalike subdomain — attacker-controlled tenant",
        "nist_800_53": ["SC-7", "SI-4", "AC-4"],
        "iso_27001":   ["A.13.1.1", "A.12.4.1"],
        "cis_v8":      ["9.2", "13.8"],
        "soc2_cc":     ["CC6.7", "CC7.2"],
        "mitre":       ["T1567.002", "T1048"],
        "severity":    "high",
    },

    # ── Endpoint / Lateral movement ──────────────────────────────────────────
    "endpoint:first_seen_host_access": {
        "label": "First-ever access to host — behavioral baseline violation",
        "nist_800_53": ["AC-6", "CM-8", "SI-4", "AU-6"],
        "iso_27001":   ["A.9.1.2", "A.12.4.1", "A.12.6.1"],
        "cis_v8":      ["16.2", "8.2", "1.1"],
        "soc2_cc":     ["CC6.3", "CC7.2"],
        "mitre":       ["T1021", "T1021.002", "T1021.006"],
        "severity":    "medium",
    },
    "endpoint:wmi_lateral_exec": {
        "label": "WMI remote process creation — lateral movement indicator",
        "nist_800_53": ["AC-6", "SI-4", "AU-12"],
        "iso_27001":   ["A.9.1.2", "A.12.4.1"],
        "cis_v8":      ["8.2", "16.2"],
        "soc2_cc":     ["CC6.3", "CC7.2"],
        "mitre":       ["T1047"],
        "severity":    "high",
    },

    # ── Identity graph / ML ──────────────────────────────────────────────────
    "token_reuse_foreign_asn": {
        "label": "OAuth refresh token reused from foreign ASN — persistent access",
        "nist_800_53": ["IA-8", "SC-8", "AC-17", "SI-4"],
        "iso_27001":   ["A.9.1.2", "A.13.1.1", "A.9.4.3"],
        "cis_v8":      ["16.5", "16.6", "9.2"],
        "soc2_cc":     ["CC6.6", "CC6.7"],
        "mitre":       ["T1550.001", "T1078.004"],
        "severity":    "high",
    },
    "token_foreign_signin": {
        "label": "Sign-in from foreign ASN — geographically anomalous authentication",
        "nist_800_53": ["IA-8", "SI-4", "AU-6"],
        "iso_27001":   ["A.9.1.2", "A.12.4.1"],
        "cis_v8":      ["16.6", "8.2"],
        "soc2_cc":     ["CC6.6"],
        "mitre":       ["T1078.004"],
        "severity":    "medium",
    },
    "identity:iso_cross_source_anomaly": {
        "label": "Cross-source isolation forest anomaly — multi-signal behavioral deviation",
        "nist_800_53": ["SI-4", "AU-6", "RA-5"],
        "iso_27001":   ["A.12.4.1", "A.16.1.1"],
        "cis_v8":      ["8.11", "17.4"],
        "soc2_cc":     ["CC7.3", "CC7.4"],
        "mitre":       [],
        "severity":    "medium",
    },
    "identity:ml_risk_spike": {
        "label": "Identity risk spike — IdentityGraph state machine elevated above threshold",
        "nist_800_53": ["SI-4", "AU-6"],
        "iso_27001":   ["A.12.4.1", "A.16.1.1"],
        "cis_v8":      ["8.11"],
        "soc2_cc":     ["CC7.3"],
        "mitre":       [],
        "severity":    "medium",
    },
    "identity:ewma_behavioral_spike": {
        "label": "EWMA behavioral residual spike — sudden activity deviation from rolling baseline",
        "nist_800_53": ["SI-4", "AU-6"],
        "iso_27001":   ["A.12.4.1"],
        "cis_v8":      ["8.11"],
        "soc2_cc":     ["CC7.2"],
        "mitre":       [],
        "severity":    "medium",
    },
}


# ─────────────────────────────────────────────────────────────────────────────
#  Public API
# ─────────────────────────────────────────────────────────────────────────────

def map_factors_to_controls(factor_tags: List[str]) -> Dict[str, Any]:
    """Return aggregated compliance violations from a cluster's factor_tags.

    Returns:
        {
          "nist_800_53": sorted list of control IDs,
          "iso_27001":   sorted list,
          "cis_v8":      sorted list,
          "soc2_cc":     sorted list,
          "mitre_techniques": sorted list,
          "violations": [{"factor": str, "label": str, "severity": str,
                          "nist_800_53": [...], ...}],
          "max_severity": "critical"|"high"|"medium"|"low"|"none",
          "control_count": int,
        }
    """
    nist: set = set()
    iso:  set = set()
    cis:  set = set()
    soc2: set = set()
    mitre: set = set()
    violations: List[Dict] = []
    _sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
    max_sev_rank = 0

    for f in factor_tags:
        m = _CONTROL_VIOLATIONS.get(str(f))
        if not m:
            continue
        nist.update(m.get("nist_800_53") or [])
        iso.update(m.get("iso_27001") or [])
        cis.update(m.get("cis_v8") or [])
        soc2.update(m.get("soc2_cc") or [])
        mitre.update(m.get("mitre") or [])
        sev = str(m.get("severity") or "medium")
        max_sev_rank = max(max_sev_rank, _sev_rank.get(sev, 0))
        violations.append({
            "factor":       f,
            "label":        m.get("label", f),
            "severity":     sev,
            "nist_800_53":  sorted(m.get("nist_800_53") or []),
            "iso_27001":    sorted(m.get("iso_27001") or []),
            "cis_v8":       sorted(m.get("cis_v8") or []),
            "soc2_cc":      sorted(m.get("soc2_cc") or []),
            "mitre":        sorted(m.get("mitre") or []),
        })

    sev_names = {v: k for k, v in _sev_rank.items()}
    return {
        "nist_800_53":      sorted(nist),
        "iso_27001":        sorted(iso),
        "cis_v8":           sorted(cis),
        "soc2_cc":          sorted(soc2),
        "mitre_techniques": sorted(mitre),
        "violations":       violations,
        "max_severity":     sev_names.get(max_sev_rank, "none"),
        "control_count":    len(nist) + len(iso),
        "mapped_factor_count": len(violations),
    }


def compliance_prompt_block(compliance_violations: Dict[str, Any]) -> str:
    """Render a compact compliance context block for persona LLM prompts."""
    if not compliance_violations or not compliance_violations.get("violations"):
        return ""
    lines = ["COMPLIANCE CONTROL VIOLATIONS (from cluster factor analysis):"]
    for v in compliance_violations["violations"][:8]:
        nist_str = ", ".join(v.get("nist_800_53") or [])
        iso_str  = ", ".join(v.get("iso_27001") or [])
        lines.append(
            f"  [{v['severity'].upper()}] {v['label']}\n"
            f"    NIST 800-53: {nist_str or 'N/A'}  |  ISO 27001: {iso_str or 'N/A'}"
        )
    soc2_str = ", ".join(compliance_violations.get("soc2_cc") or [])
    cis_str  = ", ".join(compliance_violations.get("cis_v8") or [])
    if soc2_str:
        lines.append(f"  SOC 2 Trust Criteria: {soc2_str}")
    if cis_str:
        lines.append(f"  CIS Controls v8: {cis_str}")
    lines.append(
        f"  Max severity: {compliance_violations.get('max_severity','?').upper()} "
        f"| Controls violated: {compliance_violations.get('control_count', 0)}"
    )
    return "\n".join(lines)


__all__ = ["map_factors_to_controls", "compliance_prompt_block"]
