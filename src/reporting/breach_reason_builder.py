from __future__ import annotations

from typing import Any

from src.core.ingest.evidence_assembler import iter_cluster_factors


REASON_GROUPS: tuple[dict[str, Any], ...] = (
    {
        "title": "Credential abuse confirmed",
        "factors": {"iam:as_rep_roasting", "iam:kerberoasting", "iam:golden_ticket"},
        "narrative": "AS-REP roasting, Kerberoasting, and Golden Ticket indicators show Active Directory credential compromise.",
    },
    {
        "title": "Cloud persistence confirmed",
        "factors": {"iam:oauth_consent_grant_suspicious_app", "iam:service_principal_credential_add"},
        "narrative": "OAuth consent and service principal credential changes show durable cloud access beyond one password event.",
    },
    {
        "title": "Lateral movement confirmed",
        "factors": {"endpoint:wmi_lateral_exec", "wmi_lateral_movement", "endpoint:wmi_exec_count"},
        "narrative": "WMI execution links the compromised identity to movement across internal hosts.",
    },
    {
        "title": "Exfil path confirmed",
        "factors": {"network:sharepoint_subdomain_mismatch", "cloud:sharepoint_lookalike"},
        "narrative": "Network and cloud evidence distinguishes a lookalike SharePoint tenant from expected corporate storage.",
    },
    {
        "title": "Multi-day pattern confirmed",
        "factors": {
            "recon:sustained_offhours_sequence",
            "exfil:cumulative_cloud_bytes_anomaly",
            "exfil:cumulative_bytes_anomaly",
        },
        "narrative": "ChronoGraph elevates sustained off-hours reconnaissance and cumulative outbound data movement over time.",
    },
    {
        "title": "Behavioral anomaly support",
        "factors": {"identity:ml_risk_spike", "identity:ewma_behavioral_spike"},
        "narrative": "Identity graph and anomaly-scoring features add behavioral support to the rule-based evidence.",
    },
    {
        "title": "Mailbox persistence confirmed",
        "factors": {"email:T1114.003_inbox_rule", "email:inbox_rule_external_forward"},
        "narrative": "Mailbox collection and external-forwarding rules show persistence and data staging through email.",
    },
    {
        "title": "Sensitive data access confirmed",
        "factors": {"data:sensitive_file_access"},
        "narrative": "Sensitive file access indicators show that the incident reached business data, not just authentication telemetry.",
    },
)


def build_confirmed_reasons(clusters: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    observed: set[str] = set()
    corpus_parts: list[str] = []
    for cluster in clusters or []:
        observed.update(iter_cluster_factors(cluster))
        corpus_parts.append(str(cluster))

    reasons: list[dict[str, Any]] = []
    for group in REASON_GROUPS:
        matched = sorted(observed.intersection(group["factors"]))
        if not matched:
            continue
        reasons.append(
            {
                "title": group["title"],
                "status": "confirmed",
                "factors": matched,
                "narrative": group["narrative"],
            }
        )
    corpus = " ".join(corpus_parts).lower()
    if any(token in corpus for token in ("command-and-control", "c2", "beaconing", "dns beacon")):
        reasons.append(
            {
                "title": "Command-and-control confirmed",
                "status": "confirmed",
                "factors": ["network:c2_or_beaconing_evidence"],
                "narrative": "Network evidence shows outbound command-and-control or beaconing behavior requiring containment and egress review.",
            }
        )
    return reasons
