"""ism_controls.py
==================
ASD Information Security Manual (ISM) control lookup table.

Maps security event factors → ISM control IDs + descriptions, and provides
Essential Eight maturity-level derivation from observed evidence factors.

ISM version: March 2025 (controls current as of this date; ASD updates quarterly).
Source: https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/ism

Usage
-----
    from src.core.configuration.ism_controls import (
        get_ism_controls_for_factor,
        derive_essential_eight_maturity,
        classify_iso19011_finding,
        build_corrective_action_register,
    )
"""
from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# ISM control definitions
# Each entry: (control_id, guideline_category, description)
# ---------------------------------------------------------------------------

ISM_CONTROL_DB: dict[str, tuple[str, str, str]] = {
    # Identity & Access
    "ISM-1401": ("ISM-1401", "Identity and Access Management",
                 "Legacy authentication protocols are blocked"),
    "ISM-1559": ("ISM-1559", "Identity and Access Management",
                 "MFA is used for all remote access to an organisation's systems"),
    "ISM-1173": ("ISM-1173", "Access Control Principles",
                 "Privileged access to systems is minimised"),
    "ISM-1174": ("ISM-1174", "Access Control Principles",
                 "Privileged accounts are prevented from accessing the internet"),
    "ISM-0974": ("ISM-0974", "Identity and Access Management",
                 "Service accounts are disabled when not in use"),

    # Application Control
    "ISM-1418": ("ISM-1418", "Application Control",
                 "Antivirus software uses heuristic and generic detections"),
    "ISM-1585": ("ISM-1585", "Application Control",
                 "Application control prevents execution of unapproved/malicious programs"),
    "ISM-1806": ("ISM-1806", "Application Hardening",
                 "Microsoft Office macro execution from the internet is blocked"),

    # Patching
    "ISM-1690": ("ISM-1690", "Patch Management",
                 "Security vulnerabilities in applications are patched, updated, or mitigated within 48 hours when exploits exist"),
    "ISM-1691": ("ISM-1691", "Patch Management",
                 "Security vulnerabilities in OSes are patched within 48 hours when exploits exist"),
    "ISM-1900": ("ISM-1900", "Patch Management",
                 "An automated mechanism is used to confirm and record that deployed OS patches are applied correctly"),

    # Network
    "ISM-1261": ("ISM-1261", "Network Management",
                 "Network traffic to/from identified malicious IPs is blocked"),
    "ISM-0520": ("ISM-0520", "Web Content Filtering",
                 "Outbound web traffic is proxied, inspected, and filtered"),
    "ISM-1486": ("ISM-1486", "Application Hardening",
                 "Internet Explorer 11 is disabled or removed; PowerShell is constrained"),

    # Endpoint
    "ISM-1417": ("ISM-1417", "Endpoint Device Management",
                 "Endpoint detection and response software is deployed and operated"),
    "ISM-0959": ("ISM-0959", "Endpoint Device Management",
                 "Host-based intrusion detection or prevention system is deployed"),

    # Logging & Monitoring
    "ISM-0109": ("ISM-0109", "System Monitoring",
                 "Event logs are securely stored for a minimum of 7 years"),
    "ISM-1405": ("ISM-1405", "System Monitoring",
                 "A SIEM solution is used to correlate and analyse event logs"),
    "ISM-0585": ("ISM-0585", "Audit Logging Policy",
                 "Audit logs are reviewed to identify events of interest"),

    # Data Protection
    "ISM-1511": ("ISM-1511", "Data Backup and Restoration",
                 "Backups of important data are performed and tested at least daily"),
    "ISM-1654": ("ISM-1654", "Data Management",
                 "Sensitive data is encrypted at rest and in transit"),

    # Incident Response
    "ISM-1635": ("ISM-1635", "Cyber Security Incidents",
                 "Cyber security incident response plan is current and tested annually"),
    "ISM-1720": ("ISM-1720", "Cyber Security Incidents",
                 "Post-incident reviews are conducted to identify improvements"),
}


# ---------------------------------------------------------------------------
# Factor → ISM control mapping
# ---------------------------------------------------------------------------

FACTOR_ISM_MAP: dict[str, list[str]] = {
    # Identity / credential
    "credential_harvest":        ["ISM-1401", "ISM-1559"],
    "mfa_bypass":                ["ISM-1401", "ISM-1559"],
    "legacy_auth":               ["ISM-1401"],
    "privilege_escalation":      ["ISM-1173", "ISM-1174"],
    "lateral_movement":          ["ISM-1173", "ISM-1401"],
    "lateral_movement_tool":     ["ISM-1173", "ISM-1585"],
    "rdp_lateral_movement":      ["ISM-1173", "ISM-0974"],

    # Process / endpoint
    "malicious_process":         ["ISM-1418", "ISM-1585"],
    "process_injection":         ["ISM-1585", "ISM-1486"],
    "dropper_file_write":        ["ISM-1585", "ISM-1690"],
    "masquerading_extension":    ["ISM-1418", "ISM-1806"],
    "fileless_execution":        ["ISM-1585", "ISM-1418"],

    # Network
    "c2_communication":          ["ISM-1261", "ISM-0520"],
    "c2_port":                   ["ISM-1261", "ISM-0520"],
    "external_connection":       ["ISM-0520"],
    "smb_external":              ["ISM-1261"],
    "tor_exit_node":             ["ISM-1261", "ISM-0520"],

    # Email
    "phishing_subject":          ["ISM-1806"],
    "bec_indicators":            ["ISM-1559", "ISM-1806"],
    "lookalike_sender_domain":   ["ISM-1806"],
    "reply_to_mismatch":         ["ISM-1806"],

    # Data exfiltration
    "data_exfiltration_confirmed": ["ISM-1511", "ISM-1654"],
    "c2_data_staging":           ["ISM-1511", "ISM-0520"],

    # Endpoint generic
    "impossible_travel":         ["ISM-1559", "ISM-1401"],
    "log_clearing":              ["ISM-0109", "ISM-0585"],
    "audit_trail_deletion":      ["ISM-0109"],
}


def get_ism_controls_for_factor(factor: str) -> list[tuple[str, str, str]]:
    """Return list of (control_id, category, description) for a given factor."""
    ids = FACTOR_ISM_MAP.get(factor, [])
    return [ISM_CONTROL_DB[cid] for cid in ids if cid in ISM_CONTROL_DB]


def get_ism_ids_for_factors(factors: list[str]) -> list[str]:
    """Return deduplicated ISM control IDs for a list of factors (preserving first-seen order)."""
    seen: set[str] = set()
    result: list[str] = []
    for f in (factors or []):
        for cid in FACTOR_ISM_MAP.get(f, []):
            if cid not in seen:
                seen.add(cid)
                result.append(cid)
    return result


# ---------------------------------------------------------------------------
# Essential Eight maturity derivation
# ---------------------------------------------------------------------------

# E8 control → (display_name, [factors_that_prove_failure], [ISM_control_ids])
ESSENTIAL_EIGHT: list[tuple[str, str, list[str], list[str]]] = [
    (
        "Application Control",
        "Prevents unapproved applications from executing on workstations and servers.",
        ["malicious_process", "process_injection", "fileless_execution", "dropper_file_write"],
        ["ISM-1585", "ISM-1418"],
    ),
    (
        "Patch Applications",
        "Patches or mitigates security vulnerabilities in applications.",
        ["masquerading_extension", "dropper_file_write", "c2_communication"],
        ["ISM-1690", "ISM-1691"],
    ),
    (
        "Configure Macro Settings",
        "Blocks Microsoft Office macros from the internet; restricts VBA execution.",
        ["phishing_subject", "bec_indicators", "malicious_process", "masquerading_extension"],
        ["ISM-1806"],
    ),
    (
        "Application Hardening",
        "Disables unneeded browser features (Flash, Java); constrains PowerShell/WScript.",
        ["process_injection", "fileless_execution", "dropper_file_write"],
        ["ISM-1486"],
    ),
    (
        "Restrict Admin Privileges",
        "Limits use of privileged accounts; requires separate admin/user accounts.",
        ["privilege_escalation", "lateral_movement", "lateral_movement_tool", "rdp_lateral_movement"],
        ["ISM-1173", "ISM-1174"],
    ),
    (
        "Patch Operating Systems",
        "Patches or mitigates security vulnerabilities in operating systems.",
        ["dropper_file_write", "c2_communication", "smb_external"],
        ["ISM-1900", "ISM-1691"],
    ),
    (
        "Multi-Factor Authentication",
        "Requires MFA for all remote access and privileged operations.",
        ["credential_harvest", "mfa_bypass", "legacy_auth", "impossible_travel"],
        ["ISM-1559", "ISM-1401"],
    ),
    (
        "Regular Backups",
        "Performs and tests daily backups of important data, software, and config.",
        ["data_exfiltration_confirmed", "c2_data_staging"],
        ["ISM-1511"],
    ),
]

# ML labels
_ML_LABEL = {
    0: "ML0 — Not implemented",
    1: "ML1 — Partially implemented",
    2: "ML2 — No evidence of failure (not confirmed as passing)",
    3: "ML3 — Largely implemented",
    4: "ML4 — Fully implemented",
}


def derive_essential_eight_maturity(evidence: list[dict]) -> list[dict]:
    """Derive Essential Eight maturity level (ML0–ML2 only — higher requires positive evidence).

    Returns list of dicts with keys:
        control, description, maturity_level, ml_label, evidence_codes, ism_ids, gap_exists
    """
    all_factors_by_verdict: dict[str, list[str]] = {}  # factor → list of evidence codes
    for ev in (evidence or []):
        factors = ev.get("factors") or []
        code = ev.get("code") or "?"
        verdict = ev.get("verdict") or "unknown"
        for f in factors:
            all_factors_by_verdict.setdefault(f, []).append(
                f"{code}({'M' if verdict == 'malicious' else 'S'})"
            )

    result = []
    for ctrl_name, ctrl_desc, failure_factors, ism_ids in ESSENTIAL_EIGHT:
        # Check each failure factor
        confirmed_ev: list[str] = []
        suspected_ev: list[str] = []
        for ff in failure_factors:
            refs = all_factors_by_verdict.get(ff, [])
            for ref in refs:
                if "(M)" in ref:
                    confirmed_ev.append(ref)
                elif "(S)" in ref:
                    suspected_ev.append(ref)

        if confirmed_ev:
            ml = 0
        elif suspected_ev:
            ml = 1
        else:
            # No failure evidence — can only say ML2 (insufficient to confirm ML3/4)
            ml = 2

        result.append({
            "control":        ctrl_name,
            "description":    ctrl_desc,
            "maturity_level": ml,
            "ml_label":       _ML_LABEL[ml],
            "evidence_codes": sorted(set(confirmed_ev + suspected_ev))[:6],
            "ism_ids":        ism_ids,
            "gap_exists":     ml < 2,
        })
    return result


# ---------------------------------------------------------------------------
# ISO 19011 §6.4.7 finding classification
# ---------------------------------------------------------------------------

def classify_iso19011_finding(verdict: str, factors: list[str], n_ev_same_type: int = 1) -> str:
    """Return ISO 19011 §6.4.7 classification string.

    Rules (simplified):
    - MAJOR NONCONFORMITY: malicious verdict OR systematic failure (multiple events of same type)
    - MINOR NONCONFORMITY: suspicious verdict + control gap confirmed
    - OBSERVATION: suspicious or good verdict, single instance, no confirmed control breach
    """
    _critical_factors = {
        "c2_communication", "data_exfiltration_confirmed", "mfa_bypass", "legacy_auth",
        "privilege_escalation", "lateral_movement", "lateral_movement_tool",
        "malicious_process", "process_injection", "fileless_execution",
    }
    has_critical = any(f in _critical_factors for f in (factors or []))

    if verdict == "malicious" or (has_critical and n_ev_same_type >= 2):
        return "MAJOR NONCONFORMITY"
    if verdict == "suspicious" and (factors or n_ev_same_type >= 1):
        return "MINOR NONCONFORMITY"
    return "OBSERVATION"


# ---------------------------------------------------------------------------
# Corrective Action Register (ISO 19011 §6.6)
# ---------------------------------------------------------------------------

_FINDING_DEADLINE_HOURS = {
    "MAJOR NONCONFORMITY": 24,
    "MINOR NONCONFORMITY": 720,    # 30 days
    "OBSERVATION":         2160,   # 90 days
}

_FINDING_REMEDIATION: dict[str, dict[str, str]] = {
    "c2_communication": {
        "root_cause": "Outbound traffic to C2 IP permitted — proxy/firewall rules incomplete",
        "action": "Block C2 IPs in perimeter firewall; enable DNS sinkholing for identified domains",
        "verification": "Confirm no outbound traffic to identified IPs from affected hosts",
    },
    "malicious_process": {
        "root_cause": "Application control policy does not prevent unapproved process execution",
        "action": "Deploy WDAC or AppLocker policy; enable application allowlisting on affected hosts",
        "verification": "Run test execution of previously observed process — confirm block event logged",
    },
    "mfa_bypass": {
        "root_cause": "MFA not enforced for legacy authentication protocols",
        "action": "Block legacy auth in Conditional Access / IAM policy",
        "verification": "Attempt legacy auth from external IP — confirm 401/block response",
    },
    "legacy_auth": {
        "root_cause": "Legacy authentication protocols (IMAP/POP3/SMTP AUTH) not blocked",
        "action": "Disable legacy auth protocols in identity provider Conditional Access policy",
        "verification": "Re-test legacy auth attempt — confirm blocked",
    },
    "privilege_escalation": {
        "root_cause": "Privileged account used for interactive/web activity",
        "action": "Segregate admin accounts; enable Privileged Access Workstation (PAW) policy",
        "verification": "Confirm admin accounts blocked from internet access in IAM policy",
    },
    "lateral_movement": {
        "root_cause": "Insufficient network segmentation; credential reuse across trust boundaries",
        "action": "Implement network micro-segmentation; rotate all credentials across trust zones",
        "verification": "Verify lateral movement attempt blocked between confirmed zones",
    },
    "data_exfiltration_confirmed": {
        "root_cause": "DLP policy set to Alert only; data transfer to external IP not blocked",
        "action": "Set DLP policy to Block mode for external transfers; audit sensitive data stores",
        "verification": "Confirm DLP block event fires on test transfer to external IP",
    },
    "phishing_subject": {
        "root_cause": "Email filtering rules did not quarantine phishing indicators",
        "action": "Update email gateway rules; implement DKIM/DMARC enforcement; run user awareness",
        "verification": "Send test phishing message — confirm quarantine/block",
    },
    "log_clearing": {
        "root_cause": "Log integrity controls do not prevent or detect clearing of audit logs",
        "action": "Forward logs to immutable SIEM/WORM storage; alert on log-clear events",
        "verification": "Send test log-clear event — confirm SIEM alert fires",
    },
    "impossible_travel": {
        "root_cause": "No geographic anomaly detection on authentication logs",
        "action": "Enable risky sign-in policy in identity provider; configure impossible travel alerts",
        "verification": "Confirm impossible travel alert fires in staging environment",
    },
}

_DEFAULT_REMEDIATION = {
    "root_cause": "Control configuration does not prevent or detect this activity",
    "action": "Review control policy and close identified gap",
    "verification": "Re-test with known-bad indicator — confirm block/alert fires",
}


def build_corrective_action_register(
    evidence: list[dict],
    assessment_id: str = "",
) -> list[dict]:
    """ISO 19011 §6.6 — generate a corrective action register from evidence list.

    Returns list of dicts with keys:
        finding_id, classification, factors, ism_ids, evidence_codes,
        root_cause, action, deadline_hours, verification, severity
    """
    import time as _t

    # Group evidence by primary factor
    factor_evidence: dict[str, list[dict]] = {}
    for ev in (evidence or []):
        if ev.get("verdict") not in ("malicious", "suspicious"):
            continue
        primary = ((ev.get("factors") or []) + ["unknown"])[0]
        factor_evidence.setdefault(primary, []).append(ev)

    register = []
    for idx, (factor, ev_list) in enumerate(factor_evidence.items(), start=1):
        # Use highest-severity evidence item for classification
        has_mal = any(e.get("verdict") == "malicious" for e in ev_list)
        verdict  = "malicious" if has_mal else "suspicious"
        factors  = list({f for e in ev_list for f in (e.get("factors") or [])})
        codes    = [e.get("code") for e in ev_list if e.get("code")]
        ism_ids  = get_ism_ids_for_factors(factors)
        classif  = classify_iso19011_finding(verdict, factors, len(ev_list))
        rem      = _FINDING_REMEDIATION.get(factor, _DEFAULT_REMEDIATION)
        deadline = _FINDING_DEADLINE_HOURS[classif]
        deadline_ts = _t.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            _t.gmtime(_t.time() + deadline * 3600)
        )
        register.append({
            "finding_id":     f"NCF-{idx:04d}",
            "classification": classif,
            "primary_factor": factor,
            "all_factors":    factors[:8],
            "ism_ids":        ism_ids[:4],
            "evidence_codes": codes[:6],
            "root_cause":     rem["root_cause"],
            "action":         rem["action"],
            "deadline_hours": deadline,
            "deadline_ts":    deadline_ts,
            "verification":   rem["verification"],
            "severity":       ev_list[0].get("severity") or "medium",
        })

    # Sort: Major NCF first, then Minor, then Observations
    _rank = {"MAJOR NONCONFORMITY": 0, "MINOR NONCONFORMITY": 1, "OBSERVATION": 2}
    register.sort(key=lambda r: (_rank.get(r["classification"], 3), r["finding_id"]))
    return register
