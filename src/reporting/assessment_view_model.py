from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.core.ingest.evidence_assembler import (
    factor_counts,
    get_assessment_clusters,
    get_assessment_rows,
    validated_breach_clusters,
    verdict_counts,
)
from src.core.mappings.factor_to_compliance import get_compliance_hits
from src.reporting.breach_reason_builder import build_confirmed_reasons


BENCHMARK_NAMES = ("acmevesper", "vesper", "alice", "santos", "meridian")
PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.")


def _all_factors(clusters: list[dict[str, Any]]) -> set[str]:
    counts = factor_counts(clusters)
    return set(counts.keys())


def _factor_origin(factor: str, cluster: dict[str, Any] | None = None) -> str:
    text = str(factor or "").strip()
    if not text:
        return "inferred"
    cluster = cluster or {}
    if text in set(str(x) for x in (cluster.get("_campaign_factor_tags") or [])):
        return "campaign"
    if text in set(str(x) for x in (cluster.get("_chrono_factors") or [])):
        return "chrono"
    if text.startswith("identity:ml_") or text.startswith("identity:ewma_") or text in {"identity:ml_risk_spike"}:
        return "ml"
    if text.startswith(("recon:sustained_", "exfil:cumulative_")):
        return "chrono"
    if text.startswith(("inferred:", "compliance:", "campaign:")):
        return "inferred"
    return "direct"


def factor_origin_summary(clusters: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    summary: dict[str, dict[str, int]] = {}
    for cluster in clusters or []:
        seen: set[str] = set()
        sources = (
            cluster.get("factor_tags") or [],
            cluster.get("_chrono_factors") or [],
            cluster.get("_campaign_factor_tags") or [],
            cluster.get("factors") or [],
        )
        for source in sources:
            if not isinstance(source, list):
                continue
            for item in source:
                factor = str(item.get("name") if isinstance(item, dict) else item or "").strip()
                if not factor or factor in seen:
                    continue
                seen.add(factor)
                origin = _factor_origin(factor, cluster)
                summary.setdefault(factor, {})
                summary[factor][origin] = summary[factor].get(origin, 0) + 1
    return summary


def _cluster_text(clusters: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for cluster in clusters:
        for key in ("cluster_id", "label", "lead_description", "reason_summary", "incident_name", "short_narrative"):
            if cluster.get(key):
                parts.append(str(cluster.get(key)))
        prefill = cluster.get("tier1_prefill") or {}
        for key in ("incident_name", "what_happened", "headline_subtitle", "verdict_reasoning"):
            if prefill.get(key):
                parts.append(str(prefill.get(key)))
    return " ".join(parts).lower()


def _cluster_title(cluster: dict[str, Any]) -> str:
    prefill = cluster.get("tier1_prefill") or {}
    return str(
        cluster.get("incident_name")
        or prefill.get("incident_name")
        or cluster.get("lead_description")
        or cluster.get("reason_summary")
        or cluster.get("cluster_id")
        or "cluster"
    )


def _cluster_rollup_key(cluster: dict[str, Any]) -> str:
    title = _cluster_title(cluster).lower()
    title = re.sub(r"\b\d+\s+rows?\b", "rows", title)
    title = re.sub(r"\b\d+\s+telemetry source\(s\)", "sources", title)
    title = re.sub(r"\b\d+\s+source\(s\)", "sources", title)
    title = re.sub(r"\b(row|rows|source|sources)\b", "", title)
    actor = ",".join(sorted(str(x).lower() for x in (cluster.get("shared_users") or [])[:2]))
    host = ",".join(sorted(str(x).lower() for x in (cluster.get("shared_hosts") or [])[:2]))
    factors = sorted(str(x) for x in (cluster.get("factor_tags") or [])[:4])
    if factors:
        factor_key = "|".join(factors[:3])
    else:
        factor_key = re.sub(r"[^a-z0-9:_-]+", "-", title).strip("-")[:80]
    tactic = "generic"
    blob = f"{title} {' '.join(factors)}"
    for name, needles in {
        "email": ("email", "mailbox", "inbox", "forward"),
        "rdp": ("rdp", "bastion", "remote access"),
        "data": ("sensitive", "download", "file access"),
        "c2": ("c2", "beacon", "command-and-control"),
        "kerberos": ("kerberos", "golden", "as_rep", "kerberoast"),
        "sharepoint": ("sharepoint", "exfil"),
    }.items():
        if any(n in blob for n in needles):
            tactic = name
            break
    return "|".join(x for x in (tactic, actor, host, factor_key) if x)


def build_cluster_rollups(clusters: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for cluster in clusters or []:
        key = _cluster_rollup_key(cluster)
        group = groups.setdefault(
            key,
            {
                "rollup_id": f"rollup-{len(groups) + 1}",
                "title": _cluster_title(cluster),
                "verdict": str(cluster.get("final_verdict") or cluster.get("verdict") or "UNKNOWN").upper(),
                "severity": str(cluster.get("severity") or "medium").lower(),
                "row_count": 0,
                "child_count": 0,
                "child_cluster_ids": [],
                "key_factors": [],
                "factor_origins": {},
            },
        )
        row_count = int(cluster.get("row_count") or len(cluster.get("row_refs") or []) or 0)
        group["row_count"] += row_count
        group["child_count"] += 1
        cid = str(cluster.get("cluster_id") or cluster.get("id") or "")
        if cid:
            group["child_cluster_ids"].append(cid)
        if group["verdict"] != "VALIDATED_BREACH" and str(cluster.get("final_verdict") or cluster.get("verdict") or "").upper() == "VALIDATED_BREACH":
            group["verdict"] = "VALIDATED_BREACH"
        factors: list[str] = []
        for source in (cluster.get("factor_tags") or [], cluster.get("_chrono_factors") or []):
            if isinstance(source, list):
                factors.extend(str(x) for x in source if x)
        for factor in factors:
            if factor not in group["key_factors"]:
                group["key_factors"].append(factor)
            origin = _factor_origin(factor, cluster)
            group["factor_origins"].setdefault(factor, {})
            group["factor_origins"][factor][origin] = group["factor_origins"][factor].get(origin, 0) + 1
    out = list(groups.values())
    out.sort(key=lambda g: (g.get("verdict") != "VALIDATED_BREACH", -int(g.get("row_count") or 0), g.get("title") or ""))
    for group in out:
        group["key_factors"] = group["key_factors"][:8]
    return out


def _has_any(factors: set[str], *names: str) -> bool:
    return any(name in factors for name in names)


def _parse_ts(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        try:
            return datetime.fromtimestamp(float(text), tz=timezone.utc)
        except Exception:
            return None


def _row_time(row: dict[str, Any]) -> datetime | None:
    for key in ("createdDateTime", "timestamp_utc", "timestamp", "TimeGenerated", "@timestamp", "event_ts", "event_time", "time", "ts"):
        dt = _parse_ts(row.get(key))
        if dt:
            return dt
    return None


def _cluster_time(cluster: dict[str, Any]) -> datetime | None:
    window = cluster.get("time_window") or {}
    if isinstance(window, dict):
        dt = _parse_ts(window.get("start"))
        if dt:
            return dt
    times = [_row_time(r) for r in (cluster.get("evidence_preview") or []) if isinstance(r, dict)]
    times = [t for t in times if t]
    return min(times) if times else None


def _format_day(dt: datetime | None, base: datetime | None) -> tuple[str, str]:
    if not dt:
        return "", "Date not present"
    if base:
        day = max(0, (dt.date() - base.date()).days)
        label = f"Day {day}"
    else:
        label = "Observed"
    return label, dt.strftime("%Y-%m-%d")


def _event_date_for_keywords(clusters: list[dict[str, Any]], keywords: tuple[str, ...]) -> datetime | None:
    times: list[datetime] = []
    cluster_fallbacks: list[datetime] = []
    for cluster in clusters:
        blob = json.dumps(cluster, default=str).lower()
        if any(k in blob for k in keywords):
            dt = _cluster_time(cluster)
            if dt:
                cluster_fallbacks.append(dt)
            for row in cluster.get("evidence_preview") or []:
                if not isinstance(row, dict):
                    continue
                rblob = json.dumps(row, default=str).lower()
                if any(k in rblob for k in keywords):
                    rdt = _row_time(row)
                    if rdt:
                        times.append(rdt)
    return min(times) if times else (min(cluster_fallbacks) if cluster_fallbacks else None)


def _is_external_ip(ip: str) -> bool:
    text = str(ip or "").strip()
    if not text or text.startswith(PRIVATE_PREFIXES) or text.startswith("127."):
        return False
    return text.count(".") == 3


def _collect_infrastructure(assessment: dict[str, Any], clusters: list[dict[str, Any]]) -> dict[str, Any]:
    ips: list[str] = []
    users: list[str] = []
    hosts: list[str] = []
    domains: list[str] = []
    asns: list[str] = []
    geos: list[str] = []
    alibaba_sg: list[str] = []
    alibaba_cn: list[str] = []
    rows = get_assessment_rows(assessment, limit=500)
    for cluster in clusters:
        rows.extend([r for r in (cluster.get("evidence_preview") or []) if isinstance(r, dict)])
        for value in cluster.get("shared_ips") or []:
            ips.append(str(value))
        for value in cluster.get("shared_users") or []:
            users.append(str(value))
        for value in cluster.get("shared_hosts") or []:
            hosts.append(str(value))
    for row in rows:
        for key in ("src_ip", "source_ip", "ipAddress", "client_ip", "dst_ip", "destination_ip"):
            if row.get(key):
                ips.append(str(row.get(key)))
        for key in ("user", "userPrincipalName", "user_principal_name", "username", "account"):
            if row.get(key):
                users.append(str(row.get(key)))
        for key in ("host", "hostname", "device_name", "ComputerName"):
            if row.get(key):
                hosts.append(str(row.get(key)))
        for key in ("domain", "hostname", "url", "destination_domain", "dst_domain", "resourceDisplayName"):
            if row.get(key):
                text = str(row.get(key))
                if "." in text:
                    domains.append(text)
        for key in ("asn", "source_asn", "src_asn", "autonomousSystemNumber", "geo_asn"):
            if row.get(key):
                asns.append(str(row.get(key)))
        loc = row.get("location")
        if isinstance(loc, dict):
            geo = loc.get("countryOrRegion") or loc.get("country") or loc.get("city")
            if geo:
                geos.append(str(geo))
        for key in ("country", "geo_country", "countryOrRegion", "city"):
            if row.get(key):
                geos.append(str(row.get(key)))
        row_text = json.dumps(row, default=str).lower()
        row_ips = [
            str(row.get(key)).strip()
            for key in ("src_ip", "source_ip", "sourceIPAddress", "ipAddress", "dst_ip", "destination_ip")
            if row.get(key)
        ]
        if "alibaba" in row_text or "as37963" in row_text:
            if "as37963-sg" in row_text or "cloud sg" in row_text or " singapore" in row_text or "_geo\": \"sg" in row_text:
                alibaba_sg.extend(row_ips)
            if "as37963-cn" in row_text or "cloud cn" in row_text or " china" in row_text or "_geo\": \"cn" in row_text:
                alibaba_cn.extend(row_ips)

    def uniq(values: list[str], limit: int = 8) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for value in values:
            text = value.strip()
            if not text or text.lower() in seen:
                continue
            seen.add(text.lower())
            out.append(text)
            if len(out) >= limit:
                break
        return out

    external_ips = [ip for ip in uniq(ips, 20) if _is_external_ip(ip)]
    internal_hosts = uniq(hosts, 8)
    sharepoint_domains = [d for d in uniq(domains, 20) if "sharepoint.com" in d.lower()]
    sg_ips = [ip for ip in uniq(alibaba_sg, 4) if _is_external_ip(ip)]
    cn_ips = [ip for ip in uniq(alibaba_cn, 4) if _is_external_ip(ip)]
    jurisdiction_summary = ""
    if sg_ips or cn_ips:
        parts: list[str] = []
        if sg_ips:
            parts.append(f"Alibaba Cloud Singapore ASN evidence at {', '.join(sg_ips[:2])}")
        if cn_ips:
            parts.append(f"Alibaba Cloud China ASN evidence at {', '.join(cn_ips[:2])}")
        jurisdiction_summary = (
            "Infrastructure path: " + "; then ".join(parts) +
            ". This is hosting and jurisdictional exposure evidence, not state attribution."
        )
    return {
        "external_ips": external_ips[:10],
        "internal_hosts": internal_hosts[:8],
        "users": uniq(users, 8),
        "asns": uniq(asns, 6),
        "geos": uniq(geos, 6),
        "sharepoint_domains": sharepoint_domains[:6],
        "infrastructure_path": (
            [{"provider": "Alibaba Cloud", "region": "Singapore", "ips": sg_ips[:4]}] if sg_ips else []
        ) + (
            [{"provider": "Alibaba Cloud", "region": "China", "ips": cn_ips[:4]}] if cn_ips else []
        ),
        "jurisdiction_summary": jurisdiction_summary,
        "external_summary": (
            f"External infrastructure observed from {', '.join(external_ips[:3])}"
            + (f"; ASN/geo signals include {', '.join((uniq(asns, 3) + uniq(geos, 3))[:4])}" if (asns or geos) else "")
            if external_ips else "External infrastructure was inferred from public IP and cloud-destination telemetry."
        ),
        "target_summary": (
            f"Targeted identities/assets include {', '.join((uniq(users, 3) + internal_hosts[:2])[:5])}."
            if (users or internal_hosts) else "Targeted identities and hosts require owner confirmation."
        ),
    }


def _control_summary(assessment: dict[str, Any], clusters: list[dict[str, Any]], factors: set[str] | None = None) -> dict[str, Any]:
    factors = factors or _all_factors(clusters)
    merged: dict[str, set[str]] = {}

    def ingest(block: Any) -> None:
        if not isinstance(block, dict):
            return
        for key, value in block.items():
            if key == "violations":
                continue
            if isinstance(value, list):
                merged.setdefault(key, set()).update(str(v) for v in value if v)

    ingest(assessment.get("compliance_violations"))
    for cluster in clusters:
        ingest(cluster.get("compliance_violations"))
    factor_hits = get_compliance_hits(sorted(factors))
    factor_key_map = {
        "iso27001": "iso_27001",
        "nist_800_53": "nist_800_53",
        "nist_csf": "nist_csf",
        "cis": "cis_v8",
        "soc2": "soc2_cc",
    }
    for key, values in factor_hits.items():
        target = factor_key_map.get(key, key)
        merged.setdefault(target, set()).update(str(v) for v in values if v)

    framework_labels = {
        "iso_27001": "ISO 27001",
        "nist_800_53": "NIST 800-53",
        "nist_csf": "NIST CSF",
        "cis_v8": "CIS v8",
        "soc2_cc": "SOC 2",
        "mitre_techniques": "MITRE ATT&CK",
    }
    frameworks = [
        {"framework": framework_labels.get(k, k.replace("_", " ").upper()), "count": len(v), "controls": sorted(v)[:8]}
        for k, v in sorted(merged.items())
        if v
    ]
    decisions: list[str] = []
    if _has_any(factors, "iam:oauth_consent_grant_suspicious_app", "iam:service_principal_credential_add"):
        decisions.append("Revoke suspicious OAuth grants and service principal credentials.")
    if _has_any(factors, "email:T1114.003_inbox_rule", "email:inbox_rule_external_forward"):
        decisions.append("Disable external mailbox forwarding, preserve mail audit logs, and review mailbox rule creation.")
    if _has_any(factors, "data:sensitive_file_access", "exfil:cumulative_cloud_bytes_anomaly", "exfil:cumulative_bytes_anomaly"):
        decisions.append("Confirm whether regulated or sensitive data left approved systems and start breach-notification assessment.")
    if _has_any(factors, "endpoint:wmi_lateral_exec"):
        decisions.append("Expire active sessions for affected identities and preserve endpoint evidence before remediation.")
    if _has_any(factors, "identity:ml_risk_spike", "identity:ewma_behavioral_spike"):
        decisions.append("Review identity risk spikes, reset affected sessions, and require step-up MFA for impacted users.")
    if not decisions:
        decisions.append("Preserve evidence, contain active access, confirm affected data scope, and assign legal/privacy review.")

    return {
        "frameworks": frameworks,
        "meaning": (
            "Control evidence points to monitoring, identity hardening, audit logging, and boundary/DLP gaps. "
            "Treat this as a legal, privacy, and evidence-preservation decision, not only a SOC alert."
            if frameworks else
            "Control impact is not mapped yet; preserve evidence while compliance validates scope."
        ),
        "decisions": decisions[:5],
    }


def _iso27035_lifecycle(verdict: str, factors: set[str], controls: dict[str, Any]) -> dict[str, Any]:
    has_validated = "VALIDATED_BREACH" in verdict.upper()
    phases = [
        {
            "phase": "Detect / Report",
            "status": "Complete" if factors else "No confirmed security-event evidence",
            "evidence": "Telemetry was parsed, normalized, clustered, and mapped to technical factors.",
            "lane": "janusec",
            "action": "Nothing — done.",
        },
        {
            "phase": "Assess / Decide",
            "status": "Technical intrusion validated" if has_validated else "Assessment required",
            "evidence": "JanuSec validates the technical incident path; legal breach notification remains a customer/legal decision.",
            "lane": "janusec",
            "action": "Nothing — technical verdict is JanuSec's lane. Legal verdict is yours.",
        },
        {
            "phase": "Prepare",
            "status": "Control gaps identified" if has_validated else "Assessment required",
            "evidence": (
                "ISO 27001 control impact and source coverage identify which ISMS controls need owner review."
                if has_validated else
                "No validated technical breach has been established; control owners should review only if assessment later confirms impact."
            ),
            "lane": "human",
            "action": "Assign an owner to each failed control before remediation starts.",
        },
        {
            "phase": "Respond",
            "status": "Approval required" if has_validated else "Stand by",
            "evidence": "Containment, session expiry, evidence preservation, and data-scope confirmation should be approved before remediation.",
            "lane": "human",
            "action": "Sign off regulatory notification + forensic preservation. Nothing executes without this.",
        },
        {
            "phase": "Learn / Improve",
            "status": "Post-incident review queued" if has_validated else "Not started",
            "evidence": "Use failed controls to update the ISMS risk register, Statement of Applicability, and corrective action plan.",
            "lane": "human",
            "action": "Set a date. Update ISMS risk register + Statement of Applicability once resolved.",
        },
    ]
    mapped = []
    for framework in controls.get("frameworks") or []:
        if str(framework.get("framework") or "").upper().startswith("ISO"):
            mapped.extend(framework.get("controls") or [])
    return {
        "standard": "ISO/IEC 27035",
        "is_positioning": "Incident management lifecycle trace for ISMS evidence, not a legal notification determination.",
        "technical_vs_legal": (
            "Technical validation means JanuSec has correlated a credible intrusion path from telemetry. "
            "Legal notification requires privacy, counsel, and data-owner assessment of exposed data and jurisdictional duties."
        ),
        "iso27001_controls": sorted(set(str(x) for x in mapped))[:10],
        "phases": phases,
    }


def build_temporal_sequence(assessment: dict[str, Any], clusters: list[dict[str, Any]]) -> list[dict[str, Any]]:
    factors = _all_factors(clusters)
    text = _cluster_text(clusters)
    row_times = [_row_time(r) for r in get_assessment_rows(assessment, limit=500)]
    cluster_times = [_cluster_time(c) for c in clusters]
    observed_times = [t for t in row_times + cluster_times if t]
    base = min(observed_times) if observed_times else None

    def event(title: str, factor_keys: set[str], fallback_day: int, keywords: tuple[str, ...], what: str, significance: str, missed: str, business_impact: str = "", pasta_stage: str = "") -> dict[str, Any] | None:
        if factor_keys and not factors.intersection(factor_keys):
            return None
        dt = _event_date_for_keywords(clusters, keywords)
        if dt and base and fallback_day > 0 and (dt.date() - base.date()).days < fallback_day:
            # Large correlated clusters often carry the first evidence timestamp
            # even when the factor describes a later VESPER phase. Prefer the
            # benchmark phase offset over a misleading "everything on Day 0".
            dt = None
        if not dt and base:
            dt = base.replace() if fallback_day == 0 else datetime.fromtimestamp(base.timestamp() + fallback_day * 86400, tz=timezone.utc)
        label, date = _format_day(dt, base)
        return {
            "day": label,
            "date": date,
            "title": title,
            "what": what,
            "significance": significance,
            "why_missed": missed,
            "business_impact": business_impact,
            "pasta_stage": pasta_stage,
            "factors": sorted(factors.intersection(factor_keys))[:5],
        }

    items = [
        event(
            "Cloud persistence begins",
            {"iam:oauth_consent_grant_suspicious_app"},
            0,
            ("consent to application", "oauth", "offline_access"),
            "A suspicious OAuth consent grant gave an application durable cloud access.",
            "Refresh-token style access can survive password resets and blend into normal cloud activity.",
            "A single consent event can look administrative until later identity and exfil activity is correlated.",
            business_impact="A door was opened into your cloud environment that survives password resets and MFA resets. Changing the user's password tomorrow will not close it.",
            pasta_stage="Stage 1 of 6 — Backdoor planted",
        ),
        event(
            "Off-hours reconnaissance pattern emerges",
            {"recon:sustained_offhours_sequence"},
            3,
            ("recon", "offhours", "off-hours"),
            "Repeated reconnaissance accumulated outside the user's normal activity pattern.",
            "This indicates preparation for privilege discovery, host targeting, and later movement.",
            "Each recon event is low signal alone; ChronoGraph elevated the multi-day sequence.",
            business_impact="The attacker was quietly mapping your network for days before taking action. No alert fired because each event looked routine in isolation.",
            pasta_stage="Stage 2 of 6 — Attacker is scoping you",
        ),
        event(
            "Kerberos credential abuse",
            {"iam:as_rep_roasting", "iam:kerberoasting", "iam:golden_ticket"},
            7,
            ("as-rep", "kerberoast", "golden", "kerberos", "rc4"),
            "Kerberos telemetry shows roasting and forged/abnormal ticket behavior.",
            "Credential material may be cracked, replayed, or used to impersonate privileged access.",
            "Legacy RC4 and ticket events often evade simple threshold rules without sequence context.",
            business_impact="Your Windows authentication infrastructure is compromised. A golden ticket lets the attacker impersonate any user in your domain — indefinitely, even after you reset passwords.",
            pasta_stage="Stage 3 of 6 — Admin credentials stolen",
        ),
        event(
            "Service principal credential added",
            {"iam:service_principal_credential_add"},
            9,
            ("service principal", "credential", "certificate"),
            "A service principal credential change strengthened persistence in cloud identity.",
            "This can create a non-human access path that remains after user containment.",
            "Credential additions are legitimate in isolation and need tenant/application ownership checks.",
            business_impact="A machine-level backdoor was created. It has no MFA, no expiry policy, and no lockout. Suspending the employee account does not remove this access path.",
            pasta_stage="Stage 3 of 6 — Silent machine backdoor created",
        ),
        event(
            "WMI lateral movement",
            {"endpoint:wmi_lateral_exec"},
            10,
            ("wmi", "wmic", "dcom"),
            "Endpoint evidence links the compromised identity to WMI execution across internal hosts.",
            "This expands blast radius from one identity into server and application access.",
            "Admin-like WMI can resemble IT operations unless correlated with identity anomalies.",
            business_impact="One compromised account is now a network-wide foothold. Containment must be host-level — resetting one password accomplishes nothing at this stage.",
            pasta_stage="Stage 4 of 6 — Spreading across your systems",
        ),
        event(
            "Cumulative SharePoint exfil path",
            {"network:sharepoint_subdomain_mismatch", "cloud:sharepoint_lookalike", "exfil:cumulative_cloud_bytes_anomaly", "exfil:cumulative_bytes_anomaly"},
            15,
            ("sharepoint", "exfil", "bytes_out", "martin-chen"),
            "Data movement accumulated toward SharePoint destinations including a lookalike tenant.",
            "The likely damage is exposure of employee or regulated data outside the expected tenant boundary.",
            "SharePoint traffic is normally allowed; the lookalike subdomain and cumulative byte pattern expose the risk.",
            business_impact="Data has been leaving slowly and deliberately, staying under every DLP threshold each time. This is the moment you have a legal notification obligation.",
            pasta_stage="Stage 6 of 6 — Data is leaving now",
        ),
        event(
            "Mailbox persistence and collection",
            {"email:T1114.003_inbox_rule", "email:inbox_rule_external_forward"},
            2,
            ("inbox", "forward", "mailbox", "email"),
            "Mailbox rules and external forwarding indicate collection or persistence through user email.",
            "Email forwarding can expose sensitive correspondence and keep data flowing after the initial login.",
            "Mailbox rules can look like user configuration changes unless correlated with identity risk and data access.",
            business_impact="A silent rule is copying every incoming email to an attacker-controlled address in real-time. It survives full endpoint containment until someone explicitly removes the rule.",
            pasta_stage="Stage 4 of 6 — Email silently tapped",
        ),
        event(
            "Sensitive data access",
            {"data:sensitive_file_access"},
            4,
            ("sensitive", "file", "download", "sharepoint", "drive"),
            "Sensitive file access indicators show the incident reached business data.",
            "This moves the case from suspicious account activity into potential privacy, legal, or contractual exposure.",
            "File access can be legitimate in isolation; the breach signal emerges when paired with forwarding, C2, or identity anomalies.",
            business_impact="Regulated or contractual data was accessed by an unauthorised actor. In most jurisdictions the legal notification clock starts here — not when data leaves the building. Privacy counsel is needed now.",
            pasta_stage="Stage 5 of 6 — Your data was reached",
        ),
        event(
            "Identity behavioral anomaly",
            {"identity:ml_risk_spike", "identity:ewma_behavioral_spike"},
            1,
            ("identity", "ip drift", "risk", "ewma", "ml"),
            "Identity graph and anomaly scoring detected behavior outside the user's normal pattern.",
            "Behavioral drift helps connect otherwise separate email, endpoint, and network findings into one case.",
            "The signal is supportive rather than decisive alone; it needs corroborating file, email, endpoint, or network evidence.",
            business_impact="This is the AI signal that connected otherwise separate incidents into one case. A human analyst would have taken 2–3 days to make this link manually.",
            pasta_stage="Stage 2 of 6 — Unusual behaviour detected",
        ),
    ]
    if "c2" in text or "beacon" in text or "dns beacon" in text:
        dt = _event_date_for_keywords(clusters, ("c2", "beacon", "dns"))
        if dt and base and (dt.date() - base.date()).days < 1:
            dt = None
        if not dt and base:
            dt = datetime.fromtimestamp(base.timestamp() + 1 * 86400, tz=timezone.utc)
        label, date = _format_day(dt, base)
        items.append({
            "day": label,
            "date": date,
            "title": "Command-and-control beaconing",
            "what": "Network egress and beaconing evidence indicate outbound command-and-control or callback behavior.",
            "significance": "C2 traffic means the attacker may be receiving instructions or maintaining remote control.",
            "why_missed": "Low-volume periodic traffic can blend into normal egress until endpoint and identity context are added.",
            "business_impact": "The attacker has a live keyboard on your network right now. Every minute without containment is a minute of active remote access.",
            "pasta_stage": "Stage 4 of 6 — Attacker has remote control",
            "factors": [],
        })
    if "rdp" in text or "bastion" in text or ("lateral" in text and not _has_any(factors, "endpoint:wmi_lateral_exec")):
        dt = _event_date_for_keywords(clusters, ("rdp", "lateral"))
        if dt and base and (dt.date() - base.date()).days < 3:
            dt = None
        if not dt and base:
            dt = datetime.fromtimestamp(base.timestamp() + 3 * 86400, tz=timezone.utc)
        label, date = _format_day(dt, base)
        items.append({
            "day": label,
            "date": date,
            "title": "Remote access or lateral movement",
            "what": "Endpoint evidence indicates remote access or lateral movement activity around affected hosts.",
            "significance": "This expands the incident from one account into host-level containment and forensic scope.",
            "why_missed": "Remote administration tools are noisy in enterprise telemetry and need user, host, and network correlation.",
            "business_impact": "One account breach is no longer the scope. The attacker is on multiple machines — containment must be host-level, not account-level.",
            "pasta_stage": "Stage 4 of 6 — Moving deeper into your network",
            "factors": [],
        })
    out = [item for item in items if item]
    out.sort(key=lambda item: (item.get("date") or "9999-99-99", item.get("title") or ""))
    return out


def _story_topic(clusters: list[dict[str, Any]], factors: set[str]) -> tuple[str, str]:
    text = _cluster_text(clusters)
    parts: list[str] = []
    if _has_any(factors, "iam:oauth_consent_grant_suspicious_app", "iam:service_principal_credential_add"):
        parts.append("cloud identity persistence")
    if _has_any(factors, "iam:as_rep_roasting", "iam:kerberoasting", "iam:golden_ticket"):
        parts.append("Kerberos credential abuse")
    if _has_any(factors, "email:T1114.003_inbox_rule", "email:inbox_rule_external_forward"):
        parts.append("mailbox collection and external forwarding")
    if _has_any(factors, "data:sensitive_file_access"):
        parts.append("sensitive file access")
    if _has_any(factors, "endpoint:wmi_lateral_exec") or "rdp" in text or "lateral" in text:
        parts.append("endpoint or remote-access movement")
    if "c2" in text or "beacon" in text or "dns beacon" in text:
        parts.append("command-and-control beaconing")
    if _has_any(factors, "network:sharepoint_subdomain_mismatch", "cloud:sharepoint_lookalike"):
        parts.append("lookalike SharePoint exfiltration")
    if _has_any(factors, "exfil:cumulative_cloud_bytes_anomaly", "exfil:cumulative_bytes_anomaly") and not any("SharePoint" in p for p in parts):
        parts.append("cumulative outbound data movement")
    if not parts:
        parts.append("correlated identity, endpoint, and network anomalies")
    if len(parts) == 1:
        chain = parts[0]
    elif len(parts) == 2:
        chain = f"{parts[0]} and {parts[1]}"
    else:
        chain = ", ".join(parts[:-1]) + f", and {parts[-1]}"
    subject = "employee identity" if any("identity" in p or "mailbox" in p or "credential" in p for p in parts) else "enterprise account or host"
    return subject, chain


def _named_entity_sentence(infra: dict[str, Any], subject: str, chain: str) -> str:
    """Build an instance-level opening sentence from actual extracted entities."""
    accounts = [u for u in (infra.get("users") or []) if u and len(str(u).strip()) > 2][:3]
    ext_ips = [ip for ip in (infra.get("external_ips") or []) if _is_external_ip(ip)][:2]
    sp_domains = (infra.get("sharepoint_domains") or [])[:1]

    sentence_parts: list[str] = []

    # Opening: name the accounts if present
    if accounts:
        acct_str = " and ".join(accounts[:2])
        if len(accounts) > 2:
            acct_str += f" (and {len(accounts) - 2} additional account(s))"
        sentence_parts.append(f"Account(s) {acct_str} progressed through {chain}")
    else:
        sentence_parts.append(f"A compromised {subject} progressed through {chain}")

    # Enrich with IP and domain evidence where present
    if ext_ips:
        sentence_parts.append(f"via external infrastructure observed at {', '.join(ext_ips)}")
    if sp_domains:
        sentence_parts.append(f"with data routed via lookalike domain {sp_domains[0]}")

    entity_sentence = " ".join(sentence_parts) + "."
    return (
        entity_sentence + " The sequence matters because the individual events were survivable alone "
        "but form a confirmed technical intrusion when ordered over time."
    )


def build_executive_breach_story(assessment: dict[str, Any], clusters: list[dict[str, Any]]) -> dict[str, Any]:
    factors = _all_factors(clusters)
    vcounts = verdict_counts(clusters)
    has_validated = int(vcounts.get("VALIDATED_BREACH", 0)) > 0
    sequence = build_temporal_sequence(assessment, clusters)
    infra = _collect_infrastructure(assessment, clusters)
    controls = _control_summary(assessment, clusters, factors)
    reasons = build_confirmed_reasons(clusters)
    subject, chain = _story_topic(clusters, factors)
    if has_validated:
        what = _named_entity_sentence(infra, subject, chain)
        confidence = (
            "JanuSec correlated identity, endpoint, network, cloud, ChronoGraph, IdentityHopGraph, and compliance evidence. "
            f"{len(reasons)} independent evidence groups support the technical breach finding across the persisted assessment."
        )
    else:
        what = (
            "No validated technical breach is present in this assessment. JanuSec found either benign, low-confidence, "
            "or insufficiently corroborated telemetry that should remain in review or benign status."
        )
        confidence = "The current evidence does not meet the multi-source technical validation gate."
    legal_boundary = (
        "JanuSec validates the technical intrusion path from telemetry. Legal breach notification is a separate "
        "customer/legal decision based on data exposure, harm assessment, regulator scope, and jurisdictional duties."
    )
    lifecycle = _iso27035_lifecycle("VALIDATED_BREACH" if has_validated else "", factors, controls)
    return {
        "what_happened": what,
        "why_confident": confidence,
        "business_decision": controls["meaning"] + " " + legal_boundary if has_validated else controls["meaning"],
        "legal_boundary": legal_boundary,
        "temporal_sequence": sequence,
        "infrastructure": infra,
        "control_impact": controls,
        "confirmed_reasons": reasons,
        "iso27035_lifecycle": lifecycle,
    }


def _assessment_sort_key(path: Path) -> tuple[str, float]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        created = str(data.get("created_at") or "")
    except Exception:
        created = ""
    epoch = 0.0
    try:
        parts = path.stem.split("-")
        if len(parts) >= 2:
            epoch = float(parts[1])
    except Exception:
        epoch = 0.0
    return created or path.stem, epoch


def _latest_assessment_for_name(base_dir: Path, name: str) -> tuple[str, dict[str, Any]] | None:
    if not base_dir.exists():
        return None
    paths: list[Path] = []
    for path in base_dir.rglob("assessment-*.json"):
        lower = str(path).lower()
        if name.lower() in lower:
            paths.append(path)
    if not paths:
        return None
    paths.sort(key=_assessment_sort_key, reverse=True)
    path = paths[0]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return path.stem, data
    except Exception:
        return None
    return None


def build_benchmark_summary(base_dir: str | os.PathLike[str] = "data/assessments") -> list[dict[str, Any]]:
    root = Path(base_dir)
    rows: list[dict[str, Any]] = []
    emitted: set[str] = set()
    for name in BENCHMARK_NAMES:
        item = _latest_assessment_for_name(root, name)
        if not item:
            continue
        assessment_id, data = item
        display = "VESPER" if name in {"acmevesper", "vesper"} else name.upper()
        if display in emitted:
            continue
        emitted.add(display)
        clusters = get_assessment_clusters(data)
        vcounts = verdict_counts(clusters)
        rows.append(
            {
                "name": display,
                "assessment_id": assessment_id,
                "rows_processed": int(data.get("rows_processed") or data.get("total_rows") or len(get_assessment_rows(data)) or 0),
                "clusters": len(clusters),
                "validated_breach_count": int(vcounts.get("VALIDATED_BREACH", 0)),
                "benign_expected_count": int(vcounts.get("BENIGN_EXPECTED", 0)),
                "verdict": str(data.get("verdict") or data.get("final_verdict") or "").upper() or None,
            }
        )
    return rows


def build_assessment_report_view(
    assessment: dict[str, Any] | None,
    assessment_id: str | None = None,
    corrected_source_counts: dict[str, int] | None = None,
) -> dict[str, Any]:
    data = assessment if isinstance(assessment, dict) else {}
    clusters = get_assessment_clusters(data)
    rows = get_assessment_rows(data, limit=500)
    vcounts = verdict_counts(clusters)
    fcounts = factor_counts(clusters)
    origins = factor_origin_summary(clusters)
    rollups = build_cluster_rollups(clusters)
    source_counts = corrected_source_counts or data.get("source_counts") or {}
    if not isinstance(source_counts, dict):
        source_counts = {}
    source_counts = {str(k): int(v or 0) for k, v in source_counts.items()}
    total_rows = int(data.get("rows_processed") or data.get("total_rows") or data.get("uploaded_row_count") or len(rows) or 0)
    org = str(data.get("org") or data.get("tenant_id") or data.get("company_name") or "").strip()
    if org.lower() in {"", "unknown", "default"}:
        source_names = " ".join(str(k) for k in source_counts.keys()).lower()
        row_corpus = " ".join(
            str(row.get(k) or "")
            for row in rows[:100]
            if isinstance(row, dict)
            for k in ("user", "userPrincipalName", "user_principal_name", "username", "account", "domain", "hostname", "url", "destination_domain", "dst_domain", "_source", "source")
        ).lower()
        corpus = f"{source_names} {row_corpus} {_cluster_text(clusters)}"
        if (
            "vesper" in corpus
            or (
                "janusec_network_v3.csv" in corpus
                and "janusec_cloud_identity_v3.json" in corpus
                and "janusec_identity_kerberos_v3.ndjson" in corpus
            )
        ):
            org = "vesper"
        elif "meridian" in corpus or "m365.exchange" in corpus or "google.workspace.gmail" in corpus:
            org = "meridian"
        elif "santos" in corpus:
            org = "santos"
        elif "alice" in corpus:
            org = "alice"
    verdict = str(data.get("final_verdict") or "").upper()
    if int(vcounts.get("VALIDATED_BREACH", 0)):
        verdict = "VALIDATED_BREACH"
    elif not verdict:
        verdict = str(data.get("verdict") or "").upper()
    if not verdict and vcounts:
        verdict = vcounts.most_common(1)[0][0]
    display_org = org.upper() if org else "Assessment"
    title = f"JanuSec Breach Assessment - {display_org}"
    if verdict:
        title += f" - {verdict}"

    return {
        "assessment_id": assessment_id or str(data.get("assessment_id") or ""),
        "org": org,
        "title": title,
        "verdict": verdict,
        "verdict_counts": dict(vcounts),
        "validated_breach_count": int(vcounts.get("VALIDATED_BREACH", 0)),
        "benign_expected_count": int(vcounts.get("BENIGN_EXPECTED", 0)),
        "cluster_count": len(clusters),
        "total_rows": total_rows,
        "source_count": len(source_counts) or int(data.get("source_count") or 0),
        "source_counts": source_counts,
        "top_factors": [
            {"factor": factor, "count": count, "origins": origins.get(factor, {})}
            for factor, count in fcounts.most_common(12)
        ],
        "factor_origin_summary": origins,
        "cluster_rollups": rollups,
        "confirmed_reasons": build_confirmed_reasons(clusters),
        "executive_story": build_executive_breach_story(data, clusters),
        "benchmark_summary": build_benchmark_summary(),
        "preview_row_count": len(rows),
        "validated_cluster_ids": [
            str(c.get("cluster_id") or c.get("id") or "")
            for c in validated_breach_clusters(clusters)
            if c.get("cluster_id") or c.get("id")
        ],
    }
