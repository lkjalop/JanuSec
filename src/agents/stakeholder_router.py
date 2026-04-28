"""
Stakeholder router — maps action types + evidence signals to the correct
human recipient, deadline, and regulatory citation.

The routing table uses the same evidence keywords as sabsa_coda.py and
compliance_tags.py so the three modules stay aligned.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple


# (evidence_patterns, recipient, deadline_hours, citation)
_ROUTING_TABLE: List[Tuple[List[str], str, int, str]] = [
    # Credential / identity
    (["credential", "lsass", "comsvcs", "mimikatz", "password spray",
      "mfa fatigue", "session_theft", "token replay"],
     "iam_team", 4, "APRA CPS 234 ¶36"),

    # Cloud IAM escalation
    (["assumerole", "get_secret_value", "sts", "aws_assume_role"],
     "iam_team", 4, "ISO 27001:2022 A.8.3"),

    # Container / K8s
    (["k8s_privileged_daemonset", "container_escape", "hostpid",
      "hostnetwork", "docker.sock", "kubelet"],
     "platform_sre", 8, "ISO 27001:2022 A.8.32"),

    # Mass data exfiltration / PII
    (["snowflake", "copy_into", "mass_pii_exfil", "pii", "customer",
      "manifest", "patient", "financial"],
     "legal_privacy", 720, "NDB Scheme s26WA"),  # 30 days

    # Network exfiltration
    (["network_exfil", "rclone", "mega", "backblaze", "exfil",
      "azcopy", "gsutil", "data_exfiltration", "hetzner"],
     "soc_team", 1, "NIST CSF 2.0 RS.MI-01"),

    # Pentest / engagement bridge
    (["engagement_bridge", "pentest_escalation", "pentest"],
     "ciso", 24, "ISO 27001:2022 A.5.27"),

    # APRA-regulated data
    (["apra_regulated", "apra", "cps_234"],
     "exec", 72, "APRA CPS 234 ¶38"),

    # Lateral movement
    (["lateral", "psexec", "wmiexec", "rdp", "smb", "pass the hash"],
     "soc_team", 2, "NIST CSF 2.0 PR.AC-05"),

    # Persistence / malware
    (["persistence", "scheduled task", "backdoor", "rootkit", "cobalt"],
     "soc_team", 4, "ISO 27001:2022 A.8.7"),

    # C2
    (["c2", "beacon", "dns tunnel", "command-and-control"],
     "soc_team", 1, "NIST CSF 2.0 DE.CM-01"),

    # Block IP (generic)
    (["block_ip"],
     "soc_team", 1, "NIST CSF 2.0 RS.MI-01"),

    # Disable user (generic)
    (["disable_user"],
     "iam_team", 4, "ISO 27001:2022 A.8.3"),

    # Notification
    (["notify_soc"],
     "soc_team", 1, "ISO 27001:2022 A.6.8"),

    # Regulatory notification
    (["notify_regulator"],
     "legal_privacy", 72, "NDB Scheme s26WE"),

    # Legal hold
    (["legal_hold"],
     "legal_privacy", 24, "ISO 27001:2022 A.5.31"),

    # Cross-domain data request
    (["cross_domain"],
     "ciso", 24, "ISO 27001:2022 A.5.10"),
]


def route(
    action_type: str,
    evidence_signature: str = "",
    dread_score: float = 0.0,
) -> Dict[str, Any]:
    """Route a proposed action to the correct stakeholder.

    Args:
        action_type: e.g. "block_ip", "disable_user", "notify_regulator"
        evidence_signature: concatenation of finding summary + compliance control IDs
        dread_score: DREAD score of the triggering finding

    Returns:
        {recipient, recipient_evidence, deadline_hours, citation}
    """
    combined = f"{action_type} {evidence_signature}".lower()

    best_match: Optional[Tuple[str, int, str]] = None
    best_score = 0

    for patterns, recipient, hours, citation in _ROUTING_TABLE:
        match_count = sum(1 for p in patterns if p.lower() in combined)
        if match_count > best_score:
            best_score = match_count
            best_match = (recipient, hours, citation)

    if best_match is None:
        # Default: SOC team, 8h, generic ISO reference
        return {
            "recipient": "soc_team",
            "recipient_evidence": f"Review action: {action_type}",
            "deadline_hours": 8,
            "citation": "ISO 27001:2022 A.5.26",
        }

    recipient, hours, citation = best_match

    # Build recipient evidence prose
    prose = _build_evidence_prose(action_type, evidence_signature, recipient, hours, citation)

    return {
        "recipient": recipient,
        "recipient_evidence": prose,
        "deadline_hours": hours,
        "citation": citation,
    }


def _build_evidence_prose(
    action_type: str,
    evidence_signature: str,
    recipient: str,
    hours: int,
    citation: str,
) -> str:
    """Generate human-readable prose for the UI row."""
    _TEAM_LABELS = {
        "iam_team": "IAM Team",
        "platform_sre": "Platform SRE",
        "legal_privacy": "Legal & Privacy",
        "ciso": "CISO",
        "soc_team": "SOC Team",
        "exec": "Executive Team",
        "engagement_lead": "Engagement Lead",
        "hr": "HR",
    }
    team = _TEAM_LABELS.get(recipient, recipient)

    # Format deadline
    if hours >= 720:
        deadline_str = f"{hours // 24} days"
    elif hours >= 24:
        deadline_str = f"{hours // 24}d {hours % 24}h" if hours % 24 else f"{hours // 24} days"
    else:
        deadline_str = f"{hours}h"

    # Action verb
    _ACTION_VERBS = {
        "block_ip": "block perimeter IP",
        "disable_user": "disable/rotate account",
        "notify_soc": "escalate to SOC",
        "create_incident": "create incident ticket",
        "start_capture": "initiate forensic capture",
        "push_iocs": "distribute IOCs",
        "notify_regulator": "prepare regulatory notification",
        "legal_hold": "issue legal hold",
        "cross_domain_req": "request cross-domain data",
    }
    verb = _ACTION_VERBS.get(action_type, action_type.replace("_", " "))

    # Truncate evidence for prose
    sig_short = evidence_signature[:120] if evidence_signature else "see findings"

    return f"→ {team}: {verb} within {deadline_str} ({citation}). Evidence: {sig_short}"
