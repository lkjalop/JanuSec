"""Structured LLM narrative generator for correlation clusters.

Evidence pipeline:
  - Each LLM call receives at most EVIDENCE_CAP rows (ranked by triage_score),
    preventing token explosion at 44K+ rows.
  - Evidence rows are enriched by source-type-aware semantic formatters:
    Kerberos EventID 4769+RC4 → labeled attack signal; Sysmon process-create
    with encoded command → LOLBins indicator; network flows with high bytes →
    exfil candidate.  Generic rows show inferred event type from source filename.
  - Stage 5y in assessment_worker selects evidence_preview rows by triage_score
    DESC with source-balanced sampling so no single file dominates the 20 slots.

Narrator tiers:
  - T1 (fast): default model (OLLAMA_MODEL / LLM_PROVIDER)
  - T2 (quality): JANUSEC_T2_NARRATOR_MODEL — used for top-confidence clusters
    whose narrative feeds the CEO executive summary.

Adversarial critic:
  - Enabled via JANUSEC_CRITIC_ENABLED (default 1).
  - Skipped for clusters below JANUSEC_CRITIC_MIN_CONFIDENCE (default 0.0).
  - JANUSEC_CRITIC_T1_SKIP=1 disables critic entirely on the T1 (fast) path.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time

logger = logging.getLogger(__name__)

EVIDENCE_CAP = 20       # max evidence rows fed to a single LLM call
TOP_N_CLUSTERS = int(os.getenv('JANUSEC_NARRATOR_TOP_N', '11'))
_NARRATOR_LOCK = threading.Lock()

# T2 quality narrator — used for top clusters that feed the CEO exec summary
_T2_MODEL = os.getenv('JANUSEC_T2_NARRATOR_MODEL', '')
_T2_CONFIDENCE_THRESHOLD = float(os.getenv('JANUSEC_T2_CONFIDENCE_THRESHOLD', '0.88'))

# Critic budget controls
_CRITIC_ENABLED = os.getenv('JANUSEC_CRITIC_ENABLED', '1') not in ('0', 'false', 'False')
_CRITIC_MIN_CONFIDENCE = float(os.getenv('JANUSEC_CRITIC_MIN_CONFIDENCE', '0.0'))
_CRITIC_T1_SKIP = os.getenv('JANUSEC_CRITIC_T1_SKIP', '0') in ('1', 'true', 'True')


# ── Prompt construction ───────────────────────────────────────────────────────

# ── Windows Security EventID semantic metadata ─────────────────────────────
# (label, MITRE technique, is_attack_signal when seen alone, condition notes)
_WIN_EVENT_META: dict[int, tuple[str, str, bool]] = {
    4769: ("Kerberos TGS Request", "T1558.003", False),   # attack when enc=RC4
    4768: ("Kerberos TGT Request", "T1558.004", False),   # attack when no pre-auth
    4771: ("Kerberos Pre-Auth Failed", "T1110.001", True),
    4776: ("NTLM Auth Attempt", "T1550.002", False),
    4625: ("Logon Failure", "T1110.001", False),
    4624: ("Logon Success", "T1078", False),
    4634: ("Logoff", "", False),
    4720: ("Account Created", "T1136.002", True),
    4728: ("Security Group Member Added", "T1098", True),
    4732: ("Local Group Member Added", "T1136.001", True),
    4740: ("Account Lockout", "T1110.001", True),
    4756: ("Universal Group Member Added", "T1098", True),
    1102: ("Audit Log Cleared", "T1070.001", True),
    4697: ("Service Installed", "T1543.003", True),
    7045: ("New Service Created", "T1543.003", True),
    4698: ("Scheduled Task Created", "T1053.005", True),
    4699: ("Scheduled Task Deleted", "T1070.001", True),
    4104: ("PowerShell Script Block", "T1059.001", True),
    4103: ("PowerShell Module Logging", "T1059.001", False),
    4688: ("Process Created", "T1059", False),
    4663: ("Object Access", "T1083", False),
    4657: ("Registry Value Modified", "T1112", False),
}

# Kerberos encryption type labels (ticket_encryption / enc field)
_KERB_ENC_LABELS: dict[str, str] = {
    "0x17": "RC4-HMAC(WEAK)",  "17": "RC4-HMAC(WEAK)",  "23": "RC4-HMAC(WEAK)",
    "0x18": "RC4-EXP(WEAK)",   "18": "RC4-EXP(WEAK)",   "24": "RC4-EXP(WEAK)",
    "0x1":  "DES-CRC(WEAK)",   "1":  "DES-CRC(WEAK)",
    "0x3":  "DES-MD5(WEAK)",   "3":  "DES-MD5(WEAK)",
    "0x11": "AES128",          "17": "AES128",
    "0x12": "AES256",          "18": "AES256",
}

# Source-type → source category
_SOURCE_TYPE_MAP: dict[str, str] = {
    "windows_security": "kerberos", "sysmon": "sysmon", "endpoint": "sysmon",
    "netflow": "network", "network": "network", "proxy": "network", "dns": "network",
    "cloud": "cloud", "azure": "cloud", "aws": "cloud", "okta": "cloud",
    "email": "email", "exchange": "email", "o365": "email",
}

_SOURCE_FILE_HINTS: dict[str, str] = {
    "kerberos": "kerberos", "ldap": "ldap", "ntlm": "kerberos",
    "sysmon": "sysmon", "lolbin": "sysmon", "endpoint": "sysmon", "process": "sysmon",
    "netflow": "network", "network": "network", "proxy": "network", "dns": "network",
    "cloud": "cloud", "azure": "cloud", "aws": "cloud", "okta": "cloud",
    "email": "email", "exchange": "email", "sharepoint": "email",
    "defender": "alert", "crowdstrike": "alert", "vectra": "alert",
}


def _detect_source_category(row: dict) -> str:
    """Classify a row into a source category for type-specific formatting."""
    source_type = str(row.get("source_type") or row.get("_source_type") or "").lower()
    if source_type in _SOURCE_TYPE_MAP:
        return _SOURCE_TYPE_MAP[source_type]
    source_str = str(row.get("_source") or row.get("source_file") or row.get("source_sheet") or "").lower()
    for key, cat in _SOURCE_FILE_HINTS.items():
        if key in source_str:
            return cat
    # Heuristic: if row has windows_event_id it's kerberos/security
    if row.get("windows_event_id") or row.get("event_id") and str(row.get("event_id","")).isdigit():
        return "kerberos"
    # Sysmon heuristic
    if row.get("process_name") or row.get("command_line") or row.get("sysmon_event_id"):
        return "sysmon"
    # Network heuristic
    if row.get("bytes_sent") or row.get("tls_sni") or row.get("dst_port"):
        return "network"
    # Cloud heuristic
    if row.get("userPrincipalName") or row.get("appDisplayName") or row.get("category"):
        return "cloud"
    return "generic"


def _fmt_kerberos(row: dict, ts: str, sev: str, score: float) -> str:
    """Format a Windows Security / Kerberos event row."""
    eid_raw = str(row.get("windows_event_id") or row.get("event_id") or "")
    try:
        eid = int(eid_raw)
    except ValueError:
        eid = 0
    meta_label, mitre, _ = _WIN_EVENT_META.get(eid, (f"EventID:{eid_raw}", "", False))

    enc_raw = str(row.get("ticket_encryption") or row.get("encryption_type") or "").strip().lower()
    enc_label = _KERB_ENC_LABELS.get(enc_raw, enc_raw or "AES256")
    pre_auth = str(row.get("pre_auth_type") or "2").strip()
    spn = str(row.get("service_name") or row.get("spn") or "")[:60]
    account = str(row.get("account_name") or row.get("user_canonical") or "-")
    domain = str(row.get("account_domain") or "")
    actor = f"{account}@{domain}" if domain else account
    client = str(row.get("client_address") or row.get("src_ip") or "-")
    dc = str(row.get("domain_controller") or "")

    # Determine if this is an attack signal
    attack = ""
    if eid == 4769 and "weak" in enc_label.lower():
        attack = "[KERBEROASTING] "
        mitre = "T1558.003"
    elif eid == 4768 and pre_auth in ("0", "false", "none"):
        attack = "[AS-REP ROAST] "
        mitre = "T1558.004"
    elif _WIN_EVENT_META.get(eid, ("", "", False))[2]:
        attack = "[ATTACK] "

    tech_str = f" ({mitre})" if mitre else ""
    dc_str = f" dc={dc}" if dc else ""
    return (f"[{ts}] {sev:8s} | {actor:35s} | {client:17s} | "
            f"{attack}{meta_label} eid={eid} spn={spn!r} enc={enc_label} preauth={pre_auth}"
            f"{dc_str}{tech_str} score={score:.2f}")


def _fmt_sysmon(row: dict, ts: str, sev: str, score: float) -> str:
    """Format a Sysmon / endpoint process-create row."""
    proc = str(row.get("process_name") or row.get("image") or "-")
    parent = str(row.get("parent_process") or row.get("parent_image") or "-")
    cmd = str(row.get("command_line") or "")
    host = str(row.get("host") or row.get("hostname") or row.get("computer") or "-")
    user = str(row.get("user") or row.get("user_canonical") or "-")
    sysmon_eid = str(row.get("sysmon_event_id") or "1")
    integrity = str(row.get("integrity_level") or "")

    # Detect attack patterns in command line
    attack = ""
    cmd_lower = cmd.lower()
    if "process call create" in cmd_lower and ("/node:" in cmd_lower or "wmic" in proc.lower()):
        attack = "[WMI LATERAL EXEC] "
    elif "encoded" in cmd_lower or " -enc " in cmd_lower or " -e " in cmd_lower:
        attack = "[ENCODED CMD] "
    elif any(lol in proc.lower() for lol in ("certutil", "bitsadmin", "mshta", "regsvr32", "rundll32", "msiexec")):
        attack = "[LOLBin] "
    elif "-nop" in cmd_lower and ("-w hidden" in cmd_lower or "bypass" in cmd_lower):
        attack = "[PS EVASION] "

    # Truncate command for readability — show enough to identify the technique
    remote_node = ""
    if "/node:" in cmd_lower:
        import re as _re
        m = _re.search(r'/node:(\S+)', cmd, _re.IGNORECASE)
        if m:
            remote_node = f" → EXEC:{m.group(1)}"

    cmd_snippet = cmd[:100] + ("..." if len(cmd) > 100 else "")
    integ_str = f" [{integrity}]" if integrity and integrity.lower() != "medium" else ""
    return (f"[{ts}] {sev:8s} | {user:25s} | {host:17s} | "
            f"{attack}Sysmon:{sysmon_eid} {proc}(parent:{parent}){remote_node}"
            f"{integ_str} cmd={cmd_snippet!r} score={score:.2f}")


def _fmt_network(row: dict, ts: str, sev: str, score: float) -> str:
    """Format a network flow / proxy / DNS row."""
    src_ip = str(row.get("src_ip") or row.get("src_host") or "-")
    dst_ip = str(row.get("dst_ip") or row.get("dst_host") or "-")
    dst_port = str(row.get("dst_port") or "")
    proto = str(row.get("protocol") or "").upper()
    domain = str(row.get("domain") or row.get("tls_sni") or row.get("sni") or "")
    sni = str(row.get("tls_sni") or "")
    ja3 = str(row.get("ja3_hash") or "")[:16]
    try:
        bytes_s = int(row.get("bytes_sent") or 0)
        bytes_r = int(row.get("bytes_received") or 0)
        bytes_str = f"sent={bytes_s/1024:.0f}KB recv={bytes_r/1024:.0f}KB"
        if bytes_s > 10_000_000:
            bytes_str = f"[LARGE EXFIL] sent={bytes_s/1024/1024:.1f}MB recv={bytes_r/1024/1024:.1f}MB"
    except Exception:
        bytes_str = ""

    ja3_str = f" ja3={ja3}" if ja3 else ""
    sni_str = f" sni={sni}" if sni and sni != domain else ""
    dom_str = f" domain={domain}" if domain else ""
    port_str = f":{dst_port}" if dst_port else ""
    return (f"[{ts}] {sev:8s} | -                         | {src_ip:17s} | "
            f"Net:{proto} {src_ip}→{dst_ip}{port_str}{dom_str}{sni_str}{ja3_str} {bytes_str} score={score:.2f}")


def _fmt_cloud(row: dict, ts: str, sev: str, score: float) -> str:
    """Format a cloud identity / Azure AD / OAuth event row."""
    ts_field = str(row.get("createdDateTime") or row.get("timestamp") or ts)[:19]
    upn = str(row.get("userPrincipalName") or row.get("user_canonical") or row.get("userId") or "-")
    ip = str(row.get("ipAddress") or row.get("src_ip") or "-")
    loc = row.get("location") or {}
    if isinstance(loc, dict):
        city = loc.get("city", "")
        country = loc.get("countryOrRegion", "")
        geo = f"({city},{country})" if city or country else ""
    else:
        geo = str(loc)[:20]
    category = str(row.get("category") or row.get("_source_type") or "AzureAD")
    event_name = str(row.get("event_name") or row.get("operationType") or row.get("activityDisplayName") or "")
    app = str(row.get("appDisplayName") or row.get("app_display_name") or "")

    # Detect attack patterns
    attack = ""
    evt_lower = event_name.lower()
    if "consent" in evt_lower:
        attack = "[OAUTH CONSENT] "
    elif "credential" in evt_lower or "secret" in evt_lower:
        attack = "[SP CREDENTIAL] "
    elif "impossible" in evt_lower or "impossible_travel" in str(row.get("risk_event_type","")).lower():
        attack = "[IMPOSSIBLE TRAVEL] "
    elif "risky" in str(row.get("riskState","")).lower() or float(row.get("riskScore", 0) or 0) > 60:
        attack = "[RISKY USER] "

    app_str = f" app={app!r}" if app else ""
    return (f"[{ts_field}] {sev:8s} | {upn:40s} | {ip}{geo} | "
            f"{attack}{category}: {event_name}{app_str} score={score:.2f}")


def _fmt_generic(row: dict, ts: str, sev: str, score: float) -> str:
    """Fallback formatter: extract the most informative fields available."""
    user = str(row.get("user") or row.get("user_canonical") or row.get("actor") or row.get("userPrincipalName") or "-")
    src = str(row.get("src_ip") or row.get("ip") or row.get("ipAddress") or row.get("client_address") or "-")
    event_name = (row.get("event_name") or row.get("eventName") or row.get("action") or
                  row.get("description") or row.get("operationType") or "")
    if not event_name:
        source_str = str(row.get("_source") or row.get("source_file") or row.get("source_sheet") or "").lower()
        for hint, label in _SOURCE_FILE_HINTS.items():
            if hint in source_str:
                event_name = f"{label.title()} event"
                break
        else:
            event_name = "security event"
    sheet = str(row.get("source_sheet") or row.get("_sheet") or row.get("_source") or "")[:30]
    return (f"[{ts}] {sev:8s} | {user:30s} | {src:17s} | "
            f"{str(event_name)[:120]} (from:{sheet}, score:{score:.2f})")


def _evidence_snippet(row: dict) -> str:
    """Source-aware semantic one-liner for a single evidence row.

    Dispatches to a type-specific formatter that surfaces the actual attack
    signal — Kerberos TGS+RC4, Sysmon WMI lateral exec, network exfil bytes,
    cloud OAuth consent — instead of a generic '-' placeholder.
    """
    ts = str(row.get("timestamp") or row.get("createdDateTime") or "")[:19]
    sev = str(row.get("severity") or "").upper()[:8] or "INFO    "
    score = float(row.get("triage_score") or 0)
    cat = _detect_source_category(row)

    if cat == "kerberos":
        return _fmt_kerberos(row, ts, sev, score)
    if cat == "sysmon":
        return _fmt_sysmon(row, ts, sev, score)
    if cat == "network":
        return _fmt_network(row, ts, sev, score)
    if cat == "cloud":
        return _fmt_cloud(row, ts, sev, score)
    return _fmt_generic(row, ts, sev, score)


def _compute_evidence_diagnostics(evidence: list[dict]) -> dict:
    """Compute quality metrics for the evidence set fed to the narrator."""
    if not evidence:
        return {"quality": 0.0, "rows": 0}

    source_mix: dict[str, int] = {}
    attack_signals = 0
    has_event_name = 0
    for row in evidence:
        cat = _detect_source_category(row)
        source_mix[cat] = source_mix.get(cat, 0) + 1
        # Count rows with meaningful event descriptions
        has_evt = bool(row.get("event_name") or row.get("eventName") or
                       row.get("action") or row.get("operationType") or
                       row.get("windows_event_id") or row.get("command_line") or
                       row.get("tls_sni") or row.get("bytes_sent"))
        if has_evt:
            has_event_name += 1
        # Count confirmed attack signals
        snip = _evidence_snippet(row)
        _atk_markers = ["[ATTACK]", "[KERBEROAST", "[AS-REP", "[WMI", "[ENCODED", "[LOLBin", "[OAUTH", "[SP CRED", "[IMPOSSIBLE", "[RISKY", "[PS EVAS", "[LARGE EXFIL"]
        if any(m in snip for m in _atk_markers):
            attack_signals += 1

    source_diversity = len(source_mix) / 4.0  # 4 canonical source types
    event_coverage = has_event_name / len(evidence)
    attack_density = min(1.0, attack_signals / max(1, len(evidence)) * 3)  # scale: 33% attack rows = 1.0
    quality = round((source_diversity * 0.3 + event_coverage * 0.4 + attack_density * 0.3), 3)

    return {
        "quality": quality,
        "rows": len(evidence),
        "source_mix": source_mix,
        "attack_signal_rows": attack_signals,
        "event_coverage": round(event_coverage, 3),
        "source_diversity": round(source_diversity, 3),
    }


def _compact_json(value: object, *, max_chars: int = 1600) -> str:
    try:
        text = json.dumps(value, default=str, sort_keys=True)
    except Exception:
        text = str(value)
    if len(text) > max_chars:
        return text[: max_chars - 3] + "..."
    return text


_FACTOR_TAG_LABELS: dict[str, str] = {
    # IAM / Kerberos
    "iam:kerberoasting": "Kerberoasting (T1558.003) — SPN service ticket requests for offline hash cracking",
    "iam:as_rep_roasting": "AS-REP Roasting (T1558.004) — pre-auth disabled, offline hash crack possible",
    "iam:golden_ticket": "Golden Ticket (T1558.001) — forged Kerberos TGT detected",
    "iam:silver_ticket": "Silver Ticket (T1558.002) — forged Kerberos service ticket detected",
    "iam:pass_the_hash": "Pass-the-Hash (T1550.002) — NTLM hash reuse without cleartext password",
    "iam:pass_the_ticket": "Pass-the-Ticket (T1550.003) — stolen Kerberos ticket reuse",
    "iam:credential_stuffing": "Credential stuffing — high-volume login attempts with known breach credentials",
    "iam:mfa_bypass": "MFA bypass — conditional access or push bombing circumvented",
    "iam:oauth_consent_grant_suspicious_app": "Malicious OAuth app consent grant (T1550.001) — 3rd-party app granted broad permissions",
    "iam:sp_credential_add": "Service principal credential added — new secret/cert on existing SP, persistence mechanism",
    "iam:token_replay": "Token replay attack — JWT/OAuth token reused outside expected context",
    "iam:impossible_travel": "Impossible travel — logins from geographically inconsistent locations in short time window",
    # Endpoint
    "endpoint:wmi_lateral_exec": "WMI lateral movement (T1047) — remote process creation via Windows Management Instrumentation",
    "endpoint:lolbins": "Living-off-the-land binaries (LOLBins, T1218) — legitimate OS tools used for attack",
    "endpoint:psexec_lateral": "PsExec lateral movement (T1570) — SMB-based remote execution tool",
    "endpoint:credential_dump": "Credential dumping (T1003) — LSASS/SAM/NTDS extraction",
    "endpoint:persistence_scheduled_task": "Scheduled task persistence (T1053.005)",
    "endpoint:defense_evasion_log_clear": "Log clearing (T1070.001) — Security event log 1102 cleared",
    "endpoint:service_install": "Suspicious service install (T1543.003) — EventID 7045 new service created",
    # Data / exfil
    "data:sensitive_file_access": "Sensitive file access — classified or PII files accessed outside normal pattern",
    "data:bulk_download": "Bulk data download — large volume of files retrieved in short window",
    "data:staging": "Data staging (T1074) — files aggregated in unusual location before exfil",
    "data:exfil_cloud": "Cloud exfiltration (T1567) — data sent to external cloud storage (S3, OneDrive, Dropbox)",
    # Email
    "email:inbox_rule_external_forward": "Malicious inbox rule (T1114.003) — auto-forward to external attacker-controlled address",
    "email:T1114.003_inbox_rule": "Malicious inbox rule (T1114.003) — email collection via forwarding rule",
    "email:phishing_attachment": "Spear-phishing attachment (T1566.001) — malicious file delivered via email",
    # Cloud
    "cloud:sharepoint_lookalike": "SharePoint lookalike phishing (T1566.002) — cloned SharePoint login page for credential harvest",
    "cloud:anomalous_api_access": "Anomalous cloud API access — unusual service calls outside expected application patterns",
    # Identity ML
    "identity:ml_risk_spike": "ML-detected identity risk spike — peer-group baseline deviation flagged by UBA model",
    "identity:high_risk_score": "High identity risk score — combined behavioral signals exceed risk threshold",
    # IAM (additional)
    "iam:service_principal_credential_add": "Service principal credential added (T1098.001) — new secret/cert on existing SP; persistence or privilege escalation mechanism",
    # Network
    "network:sharepoint_subdomain_mismatch": "SharePoint subdomain mismatch (T1566.002) — request to lookalike subdomain inconsistent with tenant; phishing infrastructure indicator",
    # Exfiltration
    "exfil:cumulative_bytes_anomaly": "Cumulative exfiltration anomaly (T1030/T1567) — total bytes transferred exceeds statistical baseline for this account over the window",
    "exfil:cumulative_cloud_bytes_anomaly": "Cumulative cloud exfiltration anomaly (T1567) — aggregate bytes to cloud storage (S3/OneDrive/SharePoint) exceed peer-group norm",
    # Recon
    "recon:sustained_offhours_sequence": "Sustained off-hours activity sequence (T1078) — repeated access events outside business hours over multiple days; consistent with attacker maintaining persistence",
}


def _humanize_factor_tags(cluster: dict) -> str:
    """Return a human-readable list of detected attack patterns with MITRE refs."""
    tags = cluster.get("factor_tags") or {}
    if isinstance(tags, list):
        tag_keys = tags
    elif isinstance(tags, dict):
        tag_keys = [k for k, v in tags.items() if v]
    else:
        tag_keys = []
    if not tag_keys:
        return ""
    lines = []
    for tag in tag_keys:
        label = _FACTOR_TAG_LABELS.get(tag, tag)
        lines.append(f"  - {label}")
    return "\n".join(lines)


def _cluster_signal_block(cluster: dict) -> str:
    signals: dict[str, object] = {}
    for key in (
        "_chrono_factors",
        "_chrono_first_seen",
        "_ml_scores",
        "compliance_violations",
        "phases",
        "apt_attribution",
    ):
        val = cluster.get(key)
        if val:
            signals[key] = val
    if not signals:
        return "  (no additional structured signals)"
    return _compact_json(signals)


def _build_prompt(cluster: dict, evidence_rows: list[dict]) -> str:
    cluster_id = cluster.get("cluster_id") or "unknown"

    # Deterministic pipeline verdict — anchor for the LLM
    det_verdict = str(cluster.get("final_verdict") or cluster.get("verdict") or "REQUIRES_INVESTIGATION").upper()
    det_conf = float(cluster.get("confidence") or 0.5)
    det_severity = str(cluster.get("severity") or "").upper()

    entity_summary = []
    _accounts = (cluster.get("shared_accounts") or cluster.get("shared_users")
                 or cluster.get("shared_user_accounts") or [])
    if _accounts:
        entity_summary.append("Users: " + ", ".join(str(u) for u in _accounts[:5]))
    if cluster.get("shared_ips"):
        entity_summary.append("IPs: " + ", ".join(cluster["shared_ips"][:5]))
    if cluster.get("shared_hosts"):
        entity_summary.append("Hosts: " + ", ".join(cluster["shared_hosts"][:5]))
    if cluster.get("mitre_techniques"):
        entity_summary.append("MITRE: " + ", ".join(cluster["mitre_techniques"][:5]))

    evidence_lines = "\n".join(
        f"  {i+1:3d}. {_evidence_snippet(r)}" for i, r in enumerate(evidence_rows)
    )
    entity_block = "\n".join(f"  {e}" for e in entity_summary) or "  (no shared entities extracted)"
    attack_patterns = _humanize_factor_tags(cluster)
    extra_signals = _cluster_signal_block(cluster)

    # Verdict guidance block
    if det_verdict == "VALIDATED_BREACH":
        verdict_guidance = (
            f"DETERMINISTIC CLASSIFICATION: {det_verdict} (confidence {det_conf:.2f})\n"
            "Your role is to EXPLAIN and NARRATE this confirmed breach — do not downgrade to "
            "REQUIRES_INVESTIGATION unless you can identify a specific, concrete false-positive "
            "reason. Set confidence >= 0.85 unless you have strong FP evidence."
        )
    elif det_verdict == "SUSPECTED_BREACH":
        verdict_guidance = (
            f"DETERMINISTIC CLASSIFICATION: {det_verdict} (confidence {det_conf:.2f})\n"
            "The deterministic pipeline found high-confidence breach indicators. Confirm or "
            "upgrade to VALIDATED_BREACH if the evidence clearly shows attacker actions. "
            "Set confidence >= 0.70."
        )
    else:
        verdict_guidance = (
            f"DETERMINISTIC CLASSIFICATION: {det_verdict} (confidence {det_conf:.2f})\n"
            "Classify this cluster based on the evidence and signals below."
        )

    return f"""You are a senior threat analyst. The deterministic detection pipeline has pre-classified this cluster.

{verdict_guidance}

CLUSTER ID: {cluster_id}
ROW COUNT: {cluster.get('row_count') or len(cluster.get('row_refs') or [])}
SEVERITY: {det_severity or 'UNKNOWN'}

ENTITIES INVOLVED:
{entity_block}

DETECTED ATTACK PATTERNS (from deterministic rules):
{attack_patterns or '  (none detected — use evidence rows to determine technique)'}

TOP {len(evidence_rows)} EVIDENCE ROWS (ranked by triage score):
{evidence_lines}

STRUCTURED SIGNALS FROM DETERMINISTIC PIPELINE:
{extra_signals}

Respond ONLY with valid JSON — no prose, no markdown fences:
{{
  "verdict": "<VALIDATED_BREACH | SUSPECTED_BREACH | BENIGN_EXPECTED | REQUIRES_INVESTIGATION | INSUFFICIENT_EVIDENCE>",
  "confidence": <float 0.0-1.0; must be >= 0.85 for VALIDATED_BREACH unless FP evidence present>,
  "kill_chain_stages": ["<1-3 MOST PROMINENT from: recon, delivery, exploitation, installation, c2, lateral_movement, collection, exfiltration, impact — derive from DETECTED ATTACK PATTERNS if evidence rows are generic — NEVER 'unknown' if any evidence present>"],
  "kill_chain_stage": "<dominant phase from kill_chain_stages>",
  "ioc_summary": "<1-2 sentences: specific users, IPs, hosts, MITRE techniques as IoCs — cite T-number if known>",
  "attack_narrative": "<REQUIRED 3-5 sentences: attack timeline with specific actors and techniques. Include MITRE technique IDs inline (e.g., T1047, T1558.003) where applicable. Name real users, IPs, hosts, timestamps from the evidence rows. Example: 'At 02:14 UTC, martin.chen@acme.com (10.42.4.91) requested Kerberos TGS tickets with RC4 encryption (T1558.003 Kerberoasting), indicating offline hash cracking. WMI was used to execute processes remotely on ws-martin-01 (T1047), staging the attacker for domain controller access.'>",
  "evidence_refs": [<1-based row numbers most strongly supporting verdict; include at least 3>],
  "fp_indicators": ["<specific verifiable reason this COULD be a false positive — or empty list []>"],
  "next_steps": [
    {{"priority": "P1|P2|P3", "action": "<imperative action verb phrase>", "rationale": "<why now, not later>", "tool": "<REQUIRED: exact PowerShell cmdlet, KQL query, or SPL search — never leave blank>"}}
  ]
}}"""


# ── Output parsing ────────────────────────────────────────────────────────────

_REQUIRED_KEYS = {"verdict", "confidence", "kill_chain_stage", "ioc_summary", "attack_narrative", "evidence_refs", "next_steps"}

_VALID_VERDICTS = {
    "VALIDATED_BREACH", "SUSPECTED_BREACH", "BENIGN_EXPECTED",
    "REQUIRES_INVESTIGATION", "INSUFFICIENT_EVIDENCE",
}

_VERDICT_RANK = {
    "INSUFFICIENT_EVIDENCE": 0,
    "BENIGN_EXPECTED": 1,
    "REQUIRES_INVESTIGATION": 2,
    "SUSPECTED_BREACH": 3,
    "SUSPICIOUS_ACTIVITY": 3,
    "LIKELY_COMPROMISE": 3,
    "LIKELY_BREACH": 3,
    "VALIDATED_BREACH": 4,
    "CONFIRMED_INTRUSION": 4,
    "CONFIRMED_BREACH": 4,
}

_VALID_KILL_CHAIN = {
    "recon", "weaponization", "delivery", "exploitation",
    "installation", "c2", "lateral_movement", "collection",
    "exfiltration", "impact", "unknown",
}


def _parse_llm_output(raw: str, cluster_id: str) -> dict:
    text = raw.strip()
    # Strip markdown code fences if the model wrapped the JSON
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text.rstrip())

    # Try to extract the JSON object even if there's surrounding prose
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        text = match.group(0)

    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        logger.warning("cluster_narrator: JSON parse failed for %s — using fallback", cluster_id)
        return _fallback_narrative(cluster_id, raw_text=raw[:500])

    # Validate and normalise
    verdict = str(obj.get("verdict") or "REQUIRES_INVESTIGATION").upper()
    if verdict not in _VALID_VERDICTS:
        verdict = "REQUIRES_INVESTIGATION"

    kill_chain_raw = obj.get("kill_chain_stages")
    if kill_chain_raw is None:
        kill_chain_raw = obj.get("kill_chain_stage") or []
    if isinstance(kill_chain_raw, str):
        kill_chain_values = [kill_chain_raw]
    elif isinstance(kill_chain_raw, list):
        kill_chain_values = kill_chain_raw
    else:
        kill_chain_values = []
    kill_chain_stages = []
    for stage in kill_chain_values:
        normalised = str(stage or "").strip().lower()
        if normalised in _VALID_KILL_CHAIN and normalised not in kill_chain_stages:
            kill_chain_stages.append(normalised)
        if len(kill_chain_stages) >= 3:
            break
    if not kill_chain_stages:
        kill_chain_stages = ["unknown"]
    kill_chain = kill_chain_stages[0]

    confidence = float(obj.get("confidence") or 0.5)
    confidence = max(0.0, min(1.0, confidence))

    evidence_refs = obj.get("evidence_refs") or []
    if not isinstance(evidence_refs, list):
        evidence_refs = []
    evidence_refs = [int(r) for r in evidence_refs if str(r).isdigit() or isinstance(r, int)]

    next_steps = obj.get("next_steps") or []
    if not isinstance(next_steps, list):
        next_steps = []

    fp_indicators = obj.get("fp_indicators") or []
    if not isinstance(fp_indicators, list):
        fp_indicators = []

    return {
        "verdict": verdict,
        "confidence": confidence,
        "kill_chain_stage": kill_chain,
        "kill_chain_stages": kill_chain_stages,
        "ioc_summary": str(obj.get("ioc_summary") or ""),
        "attack_narrative": str(obj.get("attack_narrative") or ""),
        "evidence_refs": evidence_refs,
        "fp_indicators": fp_indicators,
        "next_steps": next_steps,
        "_narrator_source": "llm_structured",
    }


def _fallback_narrative(cluster_id: str, *, raw_text: str = "", reason: str = "") -> dict:
    return {
        "verdict": "REQUIRES_INVESTIGATION",
        "confidence": 0.3,
        "kill_chain_stage": "unknown",
        "kill_chain_stages": ["unknown"],
        "ioc_summary": "LLM narrative unavailable — deterministic clustering only.",
        "attack_narrative": raw_text[:300] if raw_text else "",
        "evidence_refs": [],
        "fp_indicators": [],
        "next_steps": [{"priority": "P2", "action": "Manual analyst review required", "rationale": "Automated narrative generation failed", "tool": ""}],
        "_narrator_source": "fallback",
        "_narrator_error": reason,
    }


def _apply_narrative_to_cluster(cluster: dict, narrative: dict, *, upgrade_only: bool) -> None:
    """Attach narrative fields while preserving stronger deterministic verdicts."""
    cluster["llm_narrative"] = narrative

    existing_verdict = str(
        cluster.get("final_verdict") or cluster.get("verdict") or "REQUIRES_INVESTIGATION"
    ).upper()
    llm_verdict = str(narrative.get("verdict") or "REQUIRES_INVESTIGATION").upper()
    existing_rank = _VERDICT_RANK.get(existing_verdict, _VERDICT_RANK["REQUIRES_INVESTIGATION"])
    llm_rank = _VERDICT_RANK.get(llm_verdict, _VERDICT_RANK["REQUIRES_INVESTIGATION"])

    try:
        existing_confidence = float(cluster.get("confidence") or cluster.get("verdict_confidence") or 0.0)
    except Exception:
        existing_confidence = 0.0
    try:
        narrative_confidence = float(narrative.get("confidence") or 0.0)
    except Exception:
        narrative_confidence = 0.0

    selected_verdict = existing_verdict
    selected_confidence = existing_confidence
    if not upgrade_only or llm_rank > existing_rank:
        selected_verdict = llm_verdict
        selected_confidence = max(narrative_confidence, existing_confidence)
    elif llm_rank == existing_rank:
        selected_confidence = max(narrative_confidence, existing_confidence)

    cluster["final_verdict"] = selected_verdict
    cluster["verdict"] = selected_verdict
    cluster["confidence"] = max(0.0, min(1.0, selected_confidence))
    cluster["kill_chain_stage"] = narrative.get("kill_chain_stage") or "unknown"
    cluster["kill_chain_stages"] = narrative.get("kill_chain_stages") or [cluster["kill_chain_stage"]]
    cluster["ioc_summary"] = narrative.get("ioc_summary") or ""
    cluster["attack_narrative"] = narrative.get("attack_narrative") or ""
    cluster["next_steps"] = narrative.get("next_steps") or []
    cluster["fp_indicators"] = narrative.get("fp_indicators") or []
    cluster["evidence_refs_llm"] = narrative.get("evidence_refs") or []
    # _llm_evidence_refs: absolute row_index values fed to the LLM (provenance)
    # Preserved here so callers who set it before _apply_narrative_to_cluster
    # don't lose it.  narrative may carry _critic_fp_probability too.
    if "_llm_evidence_refs" not in cluster:
        cluster["_llm_evidence_refs"] = []
    if "_critic_fp_probability" in narrative:
        cluster["_critic_fp_probability"] = narrative["_critic_fp_probability"]
    # Hoist narrator source to cluster top-level so exec summary can find it
    # without walking into llm_narrative (which shallow threat_cases copies lack)
    cluster["_narrator_source"] = narrative.get("_narrator_source", "fallback")


# ── Public API ────────────────────────────────────────────────────────────────

def narrate_cluster(
    cluster: dict,
    all_evidence_rows: list[dict],
    *,
    assessment_id: str = "",
    model_override: str | None = None,
    skip_critic: bool = False,
) -> dict:
    """Generate a structured LLM narrative for one cluster.

    Args:
        cluster: cluster dict (mutated in place with narrative fields).
        all_evidence_rows: full list of ingested rows; function selects the
            top EVIDENCE_CAP by triage_score that belong to this cluster.
        assessment_id: used for tenant budget accounting.
        model_override: if set, overrides the default LLM model (T2 path).
            Pass JANUSEC_T2_NARRATOR_MODEL value for CEO-grade output.
        skip_critic: if True, skip the adversarial critic second-pass call.
    """
    # Bypass narrator for ops/pentest clusters — use rule-engine label
    if cluster.get("cluster_kind") in {"pentest", "ops"} or cluster.get("case_role"):
        narrative = _case_narrative(cluster)
        _apply_narrative_to_cluster(cluster, narrative, upgrade_only=False)
        return narrative

    cluster_id = str(cluster.get("cluster_id") or "")

    # ── Evidence selection: top EVIDENCE_CAP by triage_score, source-balanced
    candidate_idxs = set(cluster.get("row_refs") or [])
    if candidate_idxs:
        evidence = [r for r in all_evidence_rows if r.get("row_index") in candidate_idxs]
    else:
        evidence = list(all_evidence_rows)

    # Sort by triage_score then apply source-balanced cap
    evidence = sorted(evidence, key=lambda r: float(r.get("triage_score") or 0), reverse=True)
    if len(evidence) > EVIDENCE_CAP:
        # Balance: ensure attack-signal rows and all source types are represented
        attack_rows = [r for r in evidence if _detect_source_category(r) != "generic"
                       and float(r.get("triage_score") or 0) > 0]
        other_rows = [r for r in evidence if r not in attack_rows]
        balanced: list[dict] = []
        seen_cats: dict[str, int] = {}
        per_cat = max(3, EVIDENCE_CAP // max(1, len({_detect_source_category(r) for r in evidence})))
        for r in evidence:  # already sorted by score
            cat = _detect_source_category(r)
            if seen_cats.get(cat, 0) < per_cat:
                seen_cats[cat] = seen_cats.get(cat, 0) + 1
                balanced.append(r)
            if len(balanced) >= EVIDENCE_CAP:
                break
        # Fill remaining slots from highest-score rows regardless of source
        added = {id(r) for r in balanced}
        for r in evidence:
            if id(r) not in added:
                balanced.append(r)
            if len(balanced) >= EVIDENCE_CAP:
                break
        evidence = balanced[:EVIDENCE_CAP]
    else:
        evidence = evidence[:EVIDENCE_CAP]

    # Provenance + evidence diagnostics
    _llm_evidence_refs: list[int] = []
    for _r in evidence:
        _ri = _r.get("row_index")
        if _ri is not None:
            try:
                _llm_evidence_refs.append(int(float(_ri)))
            except (TypeError, ValueError):
                pass
    cluster["_llm_evidence_refs"] = _llm_evidence_refs
    cluster["_evidence_diagnostics"] = _compute_evidence_diagnostics(evidence)

    if not evidence:
        logger.warning("narrator: no evidence rows for cluster %s — fallback", cluster_id)
        narrative = _fallback_narrative(cluster_id, reason="no_evidence")
        _apply_narrative_to_cluster(cluster, narrative, upgrade_only=True)
        return narrative

    prompt = _build_prompt(cluster, evidence)

    # ── Load LLM client
    try:
        from src.integrations.llm_client import DEFAULT_CLIENT as _client
    except ImportError:
        try:
            from integrations.llm_client import DEFAULT_CLIENT as _client  # type: ignore
        except ImportError:
            logger.warning("narrator: LLM client unavailable — cluster %s fallback", cluster_id)
            narrative = _fallback_narrative(cluster_id, reason="client_unavailable")
            _apply_narrative_to_cluster(cluster, narrative, upgrade_only=True)
            return narrative

    # ── Select model: caller override → T2 env var (if cluster qualifies) → default
    selected_model: str | None = model_override
    if not selected_model and _T2_MODEL:
        cluster_conf = float(cluster.get("confidence") or 0.0)
        if cluster_conf >= _T2_CONFIDENCE_THRESHOLD:
            selected_model = _T2_MODEL
            cluster["_narrator_tier"] = "T2"
    if not selected_model:
        cluster.setdefault("_narrator_tier", "T1")

    call_timeout = float(os.getenv("JANUSEC_INGEST_LLM_TIMEOUT_S", "45"))
    t_start = time.monotonic()

    with _NARRATOR_LOCK:
        try:
            generate_kwargs: dict = {
                "max_tokens": 900 if cluster.get("_narrator_tier") == "T2" else 800,
                "tenant_id": assessment_id or "ingest",
                "overrides": {"timeout": call_timeout, "retries": 0},
            }
            if selected_model:
                generate_kwargs["model"] = selected_model
            result = _client.generate(prompt, **generate_kwargs)
        except Exception as exc:
            cause = getattr(exc, '__cause__', None)
            cause_str = f" [cause: {type(cause).__name__}: {str(cause)[:120]}]" if cause else ""
            reason = f"v3_{type(exc).__name__}: {str(exc)[:180]}{cause_str} [{type(_client).__name__}]"
            logger.warning("narrator: LLM generate failed for %s: %s%s", cluster_id, exc, cause_str, exc_info=True)
            narrative = _fallback_narrative(cluster_id, reason=reason)
            _apply_narrative_to_cluster(cluster, narrative, upgrade_only=True)
            return narrative

    narrator_elapsed = time.monotonic() - t_start
    cluster["_narrator_elapsed_s"] = round(narrator_elapsed, 2)

    if isinstance(result, dict) and result.get("error"):
        narrative = _fallback_narrative(cluster_id, reason=str(result.get("error"))[:180])
        _apply_narrative_to_cluster(cluster, narrative, upgrade_only=True)
        return narrative
    raw = result.get("text") or ""
    if not raw.strip():
        narrative = _fallback_narrative(cluster_id, reason="empty_response")
        _apply_narrative_to_cluster(cluster, narrative, upgrade_only=True)
        return narrative

    narrative = _parse_llm_output(raw, cluster_id)
    narrative["_narrator_model"] = selected_model or getattr(_client, "ollama_model", "default")
    narrative["_narrator_elapsed_s"] = round(narrator_elapsed, 2)

    # ── Adversarial critic second pass ────────────────────────────────────────
    # Controlled by: JANUSEC_CRITIC_ENABLED, JANUSEC_CRITIC_MIN_CONFIDENCE,
    # JANUSEC_CRITIC_T1_SKIP, and the skip_critic parameter.
    cluster_conf = float(cluster.get("confidence") or narrative.get("confidence") or 0.0)
    _should_critique = (
        _CRITIC_ENABLED
        and not skip_critic
        and not (_CRITIC_T1_SKIP and cluster.get("_narrator_tier") == "T1")
        and cluster_conf >= _CRITIC_MIN_CONFIDENCE
    )
    if _should_critique:
        try:
            from src.agents.critic import CRITIC as _critic
            _critique = _critic.critique(cluster, narrative, evidence, assessment_id=assessment_id)
            cluster["_critic"] = _critique
            if not _critique.get("skipped"):
                _fp_prob = float(_critique.get("fp_probability") or 0)
                _c_delta = float(_critique.get("confidence_delta") or 0)
                if _fp_prob > 0.60 or _c_delta < -0.15:
                    current_conf = float(narrative.get("confidence") or cluster_conf)
                    narrative["confidence"] = max(0.0, min(1.0, current_conf + _c_delta))
                    narrative["_critic_fp_probability"] = _fp_prob
                    logger.info("narrator: critic adjusted conf by %.2f for %s (fp_prob=%.2f)",
                                _c_delta, cluster_id, _fp_prob)
        except Exception as _ce:
            logger.debug("narrator: AdversarialCritic skipped for %s: %s", cluster_id, _ce)
            cluster["_critic"] = {"skipped": True, "skip_reason": f"import_error:{_ce}"}
    else:
        cluster.setdefault("_critic", {"skipped": True, "skip_reason": "disabled_by_config"})

    _apply_narrative_to_cluster(cluster, narrative, upgrade_only=True)
    return narrative


def _case_narrative(cluster: dict) -> dict:
    role = str(cluster.get("case_role") or "")
    kind = str(cluster.get("cluster_kind") or "")
    verdict = str(cluster.get("verdict") or cluster.get("final_verdict") or "REQUIRES_INVESTIGATION")
    confidence = float(cluster.get("confidence") or 0.5)
    if role == "primary_breach":
        stage = "exfiltration"
        next_steps = [
            {"priority": "P1", "action": "Contain affected identities and hosts", "rationale": "Validated breach case has attacker activity against crown-jewel data", "tool": "Okta/M365 disable sessions; Defender isolate device"},
            {"priority": "P1", "action": "Block exfiltration infrastructure", "rationale": "Rclone and external storage indicators are present", "tool": "Firewall/proxy block IOCs and search egress logs"},
            {"priority": "P2", "action": "Preserve data-platform and endpoint evidence", "rationale": "Evidence supports root-cause and impact determination", "tool": "Export query history, EDR process tree, and authentication logs"},
        ]
    elif role == "authorized_test":
        stage = "unknown"
        next_steps = [
            {"priority": "P3", "action": "Confirm authorized-test scope", "rationale": "High-noise activity is expected only if it matches authorisation", "tool": "Compare IPs, operators, and dates with the rules of engagement"},
        ]
    elif kind == "pentest":
        stage = "unknown"
        next_steps = [
            {"priority": "P3", "action": "Validate red-team engagement boundaries", "rationale": "The cluster is tagged as authorized testing and should remain outside breach counts when scope matches", "tool": "Compare engagement refs, operator IPs, and dates with the rules of engagement"},
        ]
    elif kind == "ops":
        stage = "unknown"
        next_steps = [
            {"priority": "P3", "action": "Validate change-management evidence", "rationale": "The cluster is tagged as expected operational activity and should remain outside breach counts when change refs match", "tool": "Compare change tickets, owners, and windows with telemetry timestamps"},
        ]
    elif role == "approved_travel":
        stage = "unknown"
        next_steps = [
            {"priority": "P3", "action": "Attach travel approval evidence", "rationale": "Travel context explains otherwise anomalous geography", "tool": "Reference TRV-2026 approval and Okta sign-in history"},
        ]
    elif role == "benign_user":
        stage = "unknown"
        next_steps = [
            {"priority": "P3", "action": "Record as benign personal VPN activity", "rationale": "Known non-enterprise activity should not remain in the analyst queue", "tool": "Tag entity and suppress matching future noise"},
        ]
    else:
        stage = "unknown"
        next_steps = []
    return {
        "verdict": verdict,
        "confidence": confidence,
        "kill_chain_stage": stage,
        "kill_chain_stages": [stage],
        "ioc_summary": str(cluster.get("headline_subtitle") or cluster.get("lead_description") or ""),
        "attack_narrative": str(cluster.get("lead_description") or ""),
        "evidence_refs": list(range(1, min(6, int(cluster.get("row_count") or 0) + 1))),
        "fp_indicators": [],
        "next_steps": next_steps,
        "_narrator_source": "deterministic_threat_case",
    }


def narrate_top_clusters(
    clusters: list[dict],
    all_evidence_rows: list[dict],
    *,
    assessment_id: str = "",
    top_n: int = TOP_N_CLUSTERS,
) -> list[dict]:
    """Narrate the top N clusters; remaining clusters keep deterministic labels.

    T2 model (JANUSEC_T2_NARRATOR_MODEL) is automatically used for the top
    cluster (by confidence × row_count) when its confidence meets
    JANUSEC_T2_CONFIDENCE_THRESHOLD — the narrative that feeds the CEO exec
    summary gets the highest-quality model.

    The stage is time-budgeted: JANUSEC_INGEST_NARRATE_TIMEOUT_S (default 50s).
    Once the budget is exhausted, remaining clusters receive fallback narratives.
    The per-call timeout is JANUSEC_INGEST_LLM_TIMEOUT_S (default 45s).
    With the adversarial critic (JANUSEC_CRITIC_TIMEOUT_S default 40s), worst-case
    per cluster is 85s; disable critic on T1 fast path with JANUSEC_CRITIC_T1_SKIP=1.

    Returns the list of narratives generated (length <= top_n).
    """
    try:
        configured_top_n = int(os.getenv("JANUSEC_INGEST_NARRATE_TOP_N", str(top_n)))
        top_n = max(0, min(int(top_n), configured_top_n))
    except Exception:
        top_n = int(top_n)
    try:
        stage_budget_s = float(os.getenv("JANUSEC_INGEST_NARRATE_TIMEOUT_S", "600"))
    except Exception:
        stage_budget_s = 600.0
    deadline = time.monotonic() + max(1.0, stage_budget_s)

    # Sort: primary by confidence (highest-risk clusters get best model + critic),
    # secondary by row_count (larger clusters have more evidence for the LLM)
    sorted_clusters = sorted(
        clusters,
        key=lambda c: (
            float(c.get("confidence") or 0),
            len(c.get("row_refs") or []),
        ),
        reverse=True,
    )
    narratives = []
    selected = sorted_clusters[:top_n]

    for idx, cluster in enumerate(selected):
        if time.monotonic() >= deadline:
            logger.warning(
                "narrator: stage budget exhausted after %d/%d clusters for %s",
                idx, len(selected), assessment_id,
            )
            for rest in selected[idx:]:
                fallback = _fallback_narrative(str(rest.get("cluster_id") or ""), reason="stage_budget_exhausted")
                _apply_narrative_to_cluster(rest, fallback, upgrade_only=True)
                narratives.append(fallback)
            break

        # T2 model for top cluster (idx=0) when env var is configured
        use_t2 = (idx == 0 and bool(_T2_MODEL))
        model_for_call = _T2_MODEL if use_t2 else None

        # Skip critic on T1 path if configured (saves ~40s per cluster on 11-cluster runs)
        skip_critic_for_call = _CRITIC_T1_SKIP and not use_t2

        try:
            n = narrate_cluster(
                cluster, all_evidence_rows,
                assessment_id=assessment_id,
                model_override=model_for_call,
                skip_critic=skip_critic_for_call,
            )
            narratives.append(n)
            if n.get("_narrator_source") == "fallback" and n.get("_narrator_error"):
                logger.warning(
                    "narrator: provider failed for %s cluster %s; aborting remaining",
                    assessment_id, cluster.get("cluster_id"),
                )
                for rest in selected[idx + 1:]:
                    fallback = _fallback_narrative(str(rest.get("cluster_id") or ""), reason="provider_failed_once")
                    _apply_narrative_to_cluster(rest, fallback, upgrade_only=True)
                    narratives.append(fallback)
                break
        except Exception as exc:
            logger.warning("narrator: exception for cluster %s: %s", cluster.get("cluster_id"), exc, exc_info=True)
            fallback = _fallback_narrative(
                str(cluster.get("cluster_id") or ""),
                reason=f"{type(exc).__name__}: {str(exc)[:180]}",
            )
            _apply_narrative_to_cluster(cluster, fallback, upgrade_only=True)
            narratives.append(fallback)
            for rest in selected[idx + 1:]:
                rest_fallback = _fallback_narrative(str(rest.get("cluster_id") or ""), reason="provider_failed_once")
                _apply_narrative_to_cluster(rest, rest_fallback, upgrade_only=True)
                narratives.append(rest_fallback)
            break

    return narratives
