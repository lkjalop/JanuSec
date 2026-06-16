"""Async assessment ingest worker for Phase 2 upload pipeline.

Responsibilities:
  1. Accept file paths from the ingest job queue.
  2. Parse each file with streaming parsers (no full-file-in-memory).
  3. Normalize rows and persist to DuckDB in batches of 1,000.
  4. Apply triage pre-filter (critical addition #1) before clustering.
  5. Run the existing _hydrate_assessment_semantics pipeline on the filtered set.
  6. Run structured LLM narratives on top-N clusters only (critical additions #2, #3).
  7. Persist the final assessment JSON using the same path as the sync handler.
  8. Emit SSE-compatible progress events throughout (critical addition #5).

The worker runs as a single long-lived asyncio.Task started during app lifespan.
Jobs are posted via _INGEST_QUEUE.  All job state is durable in DuckDB so a
worker restart can inspect incomplete jobs on startup.
"""
from __future__ import annotations

import asyncio
import datetime
import json
import logging
import os
import time
import uuid
from typing import Any, Callable

logger = logging.getLogger(__name__)

# ── Shared queue — ingest_endpoints posts here, worker consumes ────────────────
_INGEST_QUEUE: asyncio.Queue = asyncio.Queue()

# In-memory set of assessment_ids that are currently queued or running.
# Used to make enqueue_job() idempotent so that _recover_queued_jobs() and
# the upload endpoint cannot enqueue the same job twice.
_ACTIVE_JOB_IDS: set[str] = set()

# ── Triage threshold — rows below this score are noise and excluded from
#    clustering.  They remain in DuckDB and the final evidence_rows list but
#    are not fed to _build_correlation_clusters.  This is critical addition #1.
TRIAGE_MIN_FOR_CLUSTER = float(os.getenv("JANUSEC_TRIAGE_MIN_CLUSTER", "0.15"))

# How many rows max to pass to the clustering engine even after triage filter.
# Prevents the bucket-cap heuristic from running over enormous datasets.
CLUSTER_ROW_CAP = int(os.getenv("JANUSEC_CLUSTER_ROW_CAP", "25000"))
# ChronoGraph must see the FULL telemetry, not the triage-filtered subset — its whole
# job is to aggregate individually-benign events (recon commands, small uploads) into a
# pattern. Feeding it only triage-passing rows is why the VESPER recon/exfil blindspots
# never fired. Generous cap; accumulation is cheap (counter increments).
CHRONO_ROW_CAP = int(os.getenv("JANUSEC_CHRONO_ROW_CAP", "200000"))
# Absolute cumulative-bytes floor (per user, per destination, over the window) that flags
# exfil even when the z-baseline is too thin to score a slow multi-day drip. Default 2 GB
# catches a 7 GB SharePoint exfil; legitimate high-volume uploaders to allowlisted
# destinations are suppressed via the operator context channel (Phase 4).
_EXFIL_DST_BYTES_FLOOR = float(os.getenv("JANUSEC_EXFIL_DST_BYTES_FLOOR", "2000000000"))

PARSE_BATCH_SIZE = int(os.getenv("JANUSEC_PARSE_BATCH_SIZE", "5000"))
ASSESSMENT_EVIDENCE_PREVIEW_CAP = int(os.getenv("JANUSEC_ASSESSMENT_EVIDENCE_PREVIEW_CAP", "500"))

_BREACH_VERDICTS = {
    "VALIDATED_BREACH",
    "CONFIRMED_BREACH",
    "CONFIRMED_INTRUSION",
    "LIKELY_BREACH",
    "LIKELY_COMPROMISE",
    "SUSPECTED_BREACH",
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


def _calibrate_cluster_confidence(cluster: dict) -> None:
    """Post-hoc evidence-weight confidence floor for fallback narratives.

    When the LLM is unavailable, cluster_narrator._fallback_narrative() hard-codes
    confidence=0.3 regardless of evidence volume.  This function raises the floor
    using a simple sigmoid over evidence count × triage score so that a 49-row
    VALIDATED_BREACH cluster is not presented with the same confidence as a 2-row
    REQUIRES_INVESTIGATION cluster.

    LLM-generated confidence is left untouched.
    """
    if cluster.get("_narrator_source") != "fallback":
        return  # LLM-generated confidence stands as-is

    verdict = str(cluster.get("final_verdict") or cluster.get("verdict") or "").upper()
    evidence_count = int(
        cluster.get("row_count")
        or len(cluster.get("row_refs") or [])
        or 0
    )
    triage_score = float(
        cluster.get("triage_score")
        or cluster.get("max_triage_score")
        or 0.0
    )

    # Corroboration signals — a fallback verdict backed by MULTIPLE telemetry sources
    # and/or a cross-cluster kill-chain progression is more trustworthy than a single-
    # source one. (LLM-narrated clusters already factor these via the prompt, so this
    # boost applies only on the fallback path and cannot double-count.)
    _sources = cluster.get("sources") or cluster.get("source_types") or []
    source_count = len(set(_sources)) if isinstance(_sources, (list, set, tuple)) else 0
    has_campaign_link = bool(cluster.get("_campaign_links"))

    # Calibration weight: evidence + triage (base) + corroboration (sources + linkage).
    # Base terms scale 0→1 over 20 rows and the triage range; corroboration adds up to
    # 0.20 (≈3+ sources) and 0.10 (linked) so strongly-corroborated fallbacks floor higher.
    base = min(1.0, evidence_count / 20.0) * 0.625 + min(1.0, triage_score) * 0.375
    corroboration = min(0.20, max(0, source_count - 1) * 0.10) + (0.10 if has_campaign_link else 0.0)
    weight = min(1.0, base + corroboration)

    if verdict in {"VALIDATED_BREACH", "CONFIRMED_BREACH", "CONFIRMED_INTRUSION"}:
        floor = 0.55 + weight * 0.25   # 0.55 → 0.80 (at weight=1.0)
    elif verdict in {"SUSPECTED_BREACH", "LIKELY_BREACH", "LIKELY_COMPROMISE"}:
        floor = 0.40 + weight * 0.20   # 0.40 → 0.60 (at weight=1.0)
    elif verdict == "REQUIRES_INVESTIGATION":
        floor = 0.30 + weight * 0.10   # 0.30 → 0.40 (at weight=1.0)
    else:
        floor = 0.20                    # benign/insufficient: stay low

    current = float(cluster.get("confidence") or 0.0)
    if floor > current:
        cluster["confidence"] = round(min(1.0, floor), 3)
        cluster["_confidence_calibrated"] = True


def _cluster_source_count(cluster: dict) -> int:
    sources = cluster.get("sources") or cluster.get("shared_sources") or []
    if isinstance(sources, dict):
        return len(sources)
    if isinstance(sources, (list, tuple, set)):
        source_count = len({str(s) for s in sources if s})
        if source_count:
            return source_count
    phases = cluster.get("phases") or []
    if isinstance(phases, list):
        phase_sources = {
            str(source)
            for phase in phases
            if isinstance(phase, dict)
            for source in (phase.get("sources") or [])
            if source
        }
        if phase_sources:
            return len(phase_sources)
    try:
        return int(cluster.get("source_count") or 0)
    except Exception:
        return 0


def _cluster_row_count(cluster: dict) -> int:
    try:
        return int(cluster.get("row_count") or len(cluster.get("row_refs") or []))
    except Exception:
        return 0


def _cluster_verdict(cluster: dict) -> str:
    return str(cluster.get("final_verdict") or cluster.get("verdict") or "").upper()


def _is_breach_cluster(cluster: dict) -> bool:
    verdict = _cluster_verdict(cluster)
    if verdict in _BREACH_VERDICTS:
        return True
    if verdict == "REQUIRES_INVESTIGATION":
        return (
            _cluster_source_count(cluster) >= 2
            or _cluster_row_count(cluster) >= 50
            or int(cluster.get("phase_count") or 0) >= 2
        )
    return False


_VPS_ASN_TERMS = (
    "akamai", "alibaba", "amazon", "aws", "azure", "backblaze", "choopa",
    "cloudflare", "cloudfront", "contabo", "datacamp", "digitalocean",
    "google cloud", "google llc", "hetzner", "leaseweb", "linode", "m247",
    "mega", "microsoft", "ovh", "packet", "scaleway", "vultr", "wasabi",
)


def _row_text(row: dict) -> str:
    try:
        return json.dumps(row, default=str).lower()
    except Exception:
        return str(row).lower()


def _row_ts(row: dict) -> datetime.datetime | None:
    for key in ("timestamp_utc", "timestamp", "@timestamp", "event_time", "eventTime", "time", "ts", "created_at"):
        value = row.get(key)
        if value in (None, ""):
            continue
        if isinstance(value, (int, float)):
            try:
                ts = float(value) / 1000.0 if float(value) > 1e12 else float(value)
                return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
            except Exception:
                continue
        try:
            parsed = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=datetime.timezone.utc)
            return parsed
        except Exception:
            continue
    return None


def _row_user(row: dict) -> str:
    for key in (
        "user_canonical", "user_principal_name", "userPrincipalName", "username",
        "user_name", "account", "actor", "user", "initiator", "email",
    ):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
        if isinstance(value, dict):
            inner = value.get("alternateId") or value.get("login") or value.get("id") or value.get("email")
            if inner:
                return str(inner).strip().lower()
    return ""


def _row_country(row: dict) -> str:
    geo = row.get("_geo") if isinstance(row.get("_geo"), dict) else {}
    for key in (
        "country_code", "geo_country_code", "geoip_country_code", "src_country",
        "dst_country", "country", "geo_country", "geo_src_country", "geo_dst_country",
    ):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().upper()
    for key in ("country_code", "country", "src_country", "dst_country"):
        value = geo.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().upper()
    return ""


def _row_asn_org(row: dict) -> str:
    geo = row.get("_geo") if isinstance(row.get("_geo"), dict) else {}
    for key in (
        "as_org", "asn_org", "asn_organization", "isp", "geo_isp",
        "autonomous_system_organization", "source_as_org", "src_as_org",
        "destination_as_org", "geo_dst_org",
    ):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    for key in ("as_org", "asn_org", "isp", "src_org", "dst_org"):
        value = geo.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _row_ips(row: dict) -> list[str]:
    values: list[str] = []
    for key in (
        "src_ip", "source_ip", "client_ip", "remote_address", "ip_address",
        "dst_ip", "destination_ip", "dest_ip", "ip_dst", "server_ip",
    ):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            values.append(value.strip())
    return values


def _is_public_ip(value: str) -> bool:
    try:
        import ipaddress
        ip = ipaddress.ip_address(value)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)
    except Exception:
        return False


def _derive_santos_tier2_aliases(cluster: dict, rows: list[dict]) -> None:
    """Populate deterministic Tier-2 flags consumed by breach.html quality checks."""
    texts = [_row_text(row) for row in rows[:200]]
    combined = " ".join(texts)
    explicit_travel = any(term in combined for term in ("impossible travel", "geo-velocity", "geovelocity", "newcountry"))
    travel_details: list[dict] = []
    by_user: dict[str, list[tuple[datetime.datetime, str, int]]] = {}
    for row in rows:
        user = _row_user(row)
        country = _row_country(row)
        ts = _row_ts(row)
        if user and country and ts:
            try:
                idx = int(float(row.get("row_index", row.get("row_number", -1))))
            except Exception:
                idx = -1
            by_user.setdefault(user, []).append((ts, country, idx))
    for user, events in by_user.items():
        ordered = sorted(events, key=lambda item: item[0])
        for prev, cur in zip(ordered, ordered[1:]):
            prev_ts, prev_country, prev_idx = prev
            cur_ts, cur_country, cur_idx = cur
            hours = abs((cur_ts - prev_ts).total_seconds()) / 3600.0
            if prev_country and cur_country and prev_country != cur_country and hours <= 12:
                travel_details.append({
                    "user": user,
                    "from_country": prev_country,
                    "to_country": cur_country,
                    "hours_between": round(hours, 2),
                    "row_index_from": prev_idx,
                    "row_index_to": cur_idx,
                })
                break
    cluster["_impossible_travel"] = bool(explicit_travel or travel_details)
    if travel_details:
        cluster["_impossible_travel_detail"] = travel_details[:5]

    vps_details: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        org = _row_asn_org(row)
        org_l = org.lower()
        row_has_vps = any(term in org_l for term in _VPS_ASN_TERMS)
        text_has_vps = any(term in _row_text(row) for term in _VPS_ASN_TERMS)
        if not row_has_vps and not text_has_vps:
            continue
        public_ips = [ip for ip in _row_ips(row) if _is_public_ip(ip)]
        if not public_ips and not org:
            continue
        for ip in public_ips or [""]:
            key = (ip, org)
            if key in seen:
                continue
            seen.add(key)
            vps_details.append({"ip": ip, "asn_org": org or "cloud/VPS provider"})
            if len(vps_details) >= 8:
                break
        if len(vps_details) >= 8:
            break
    cluster["_commercial_vps"] = bool(vps_details)
    if vps_details:
        cluster["_commercial_vps_detail"] = vps_details


def _sync_cluster_prefill_aliases(cluster: dict) -> None:
    prefill = cluster.get("tier1_prefill") or {}
    alias_pairs = (
        ("dread_score", "dread_score"),
        ("diamond_model", "diamond_model"),
        ("kill_chain_summary", "kill_chain_summary"),
        ("event_chain_summary", "event_chain_summary"),
        ("pasta_summary", "pasta_summary"),
        ("known_technical", "known_technical"),
        ("unknown_technical", "unknown_technical"),
    )
    for source_key, target_key in alias_pairs:
        value = prefill.get(source_key)
        if value not in (None, "", [], {}):
            cluster[target_key] = value
    if "adversarial_sequence" in prefill:
        cluster["_adversarial_sequence"] = bool(prefill.get("adversarial_sequence"))
        if prefill.get("adversarial_sequence_detail"):
            cluster["_adversarial_sequence_detail"] = prefill.get("adversarial_sequence_detail")


def _coerce_event_ts(value: Any) -> float | str | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return float(value) / 1000.0 if float(value) > 1e12 else float(value)
    try:
        return datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except Exception:
        return value


def _hopgraph_event_from_row(row: dict) -> dict:
    event = dict(row)
    event.setdefault("src_host", row.get("src_host") or row.get("source_host") or row.get("hostname") or row.get("host") or row.get("device_name"))
    event.setdefault("host", event.get("src_host") or row.get("dest_host") or row.get("dst_host"))
    event.setdefault("process", row.get("process") or row.get("process_name") or row.get("image") or row.get("exe"))
    event.setdefault("dst_ip", row.get("dst_ip") or row.get("destination_ip") or row.get("dest_ip") or row.get("ip_dst") or row.get("server_ip"))
    event.setdefault("src_ip", row.get("src_ip") or row.get("source_ip") or row.get("client_ip") or row.get("ip_src"))
    event.setdefault("domain", row.get("domain") or row.get("domain_name") or row.get("dns_query") or row.get("query"))
    if not event.get("domain") and row.get("url"):
        try:
            from urllib.parse import urlparse
            event["domain"] = urlparse(str(row.get("url"))).hostname or None
        except Exception:
            pass
    event.setdefault("file_hash", row.get("file_hash") or row.get("sha256") or row.get("hash"))
    ts = (
        row.get("timestamp")
        or row.get("event_time")
        or row.get("eventTime")
        or row.get("time")
        or row.get("@timestamp")
    )
    coerced_ts = _coerce_event_ts(ts)
    if coerced_ts is not None:
        event["timestamp"] = coerced_ts
    return event


# ── Progress callback type ─────────────────────────────────────────────────────
ProgressFn = Callable[[str, str, int, str], None]  # (assessment_id, stage, percent, label)


def _noop_progress(aid: str, stage: str, pct: int, label: str) -> None:
    pass


# ── Normalisation wrapper ──────────────────────────────────────────────────────

def _normalize_ingest_row(raw: dict, row_index: int) -> dict:
    """Apply streaming_ingest normalizer if available, else minimal fallback."""
    try:
        from src.pipeline.streaming_ingest import normalize_row as _nr
        row = _nr(raw)
    except Exception:
        row = dict(raw)

    row["row_index"] = row_index
    row.setdefault("_source", raw.get("_source", ""))
    row.setdefault("source_file", raw.get("_source", ""))
    if not row.get("source_type"):
        row["source_type"] = raw.get("source_type") or raw.get("_source_type") or row.get("_source_type") or ""

    row["triage_score"] = _score_async_ingest_row(raw, row)

    # Normalize windows_security (Kerberos/WinEvent) field names so cluster pivots can link
    # these rows to endpoint and network sources by user and IP.
    _src_type = row.get("source_type") or raw.get("source_type") or raw.get("_source_type") or ""
    if _src_type == "windows_security":
        # account_name is the Kerberos requester (TGT=user, TGS=user requesting service ticket)
        # Machine accounts end with "$" — skip them for user pivot.
        if not row.get("user_canonical") and not row.get("user"):
            _acct = raw.get("account_name") or row.get("account_name", "")
            if _acct and not str(_acct).endswith("$"):
                row["user_canonical"] = str(_acct).strip().lower()
        # client_address is the IP of the machine making the Kerberos request
        if not row.get("src_ip"):
            _ca = raw.get("client_address") or row.get("client_address", "")
            if _ca and str(_ca) not in ("::1", "127.0.0.1", ""):
                row["src_ip"] = str(_ca).strip()
        # workstation is the client machine name (complement to client_address)
        if not row.get("host"):
            _ws = raw.get("workstation") or row.get("workstation", "")
            if _ws:
                row["host"] = str(_ws).strip()

    return row


_HIGH_SIGNAL_TERMS = (
    # Credential theft / LSASS
    "lsass", "comsvcs", "mimikatz", "procdump", "ntds",
    # Lateral movement / execution
    "psexec", "wmiexec", "invoke-expression", "encoded command",
    # Cloud data exfil (source tool names excluded — match verb/service, not vendor)
    "copy into", "external stage", "rclone", "mega.nz",
    # Network / C2
    "impossible travel", "command-and-control", "c2 beacon",
    # C2 implant frameworks and network threat indicators
    "sliver", "havoc", "mythic", "brute ratel", "anomalous ja3",
    # Zone-based attacker classification labels
    "attacker_c2", "attacker_infra",
    # Identity / access
    "password spray", "privilege escalation",
    # Malware / tools
    "cobalt strike", "daemonset", "pentest",
    # Cloud privilege / secret abuse (CloudTrail phase detector terms)
    "getsecretvalue", "secretsmanager", "assumerole", "assumerolewithsaml",
    "getfederationtoken", "putbucketpolicy", "putrolepolicy",
    # CloudTrail tampering / defense evasion
    "deletetrail", "stoprecording", "disablekey", "deletebucketpolicy",
    "stopinstances", "terminateinstances",
    # Okta / Entra risk indicators (broad terms removed: "mfa", "credential" match BAU auth)
    "newcountry", "newdevice", "mfafailure", "suspicious", "atypical",
    # K8s escape signals
    "hostpid", "hostnetwork", "hostipc", "docker.sock",
    # IAM / email exfiltration signals (Sprint 1 additions — Meridian scenario)
    "new-inboxrule", "newinboxrule", "forwardto", "forwarding_smtp",
    "externalaccess", "sensitive_document_bulk_download", "ccp-exfil",
    # Bastion / RDP lateral movement
    "mstsc", "mstsc.exe", "remote desktop",
)

# Security-relevant cloud/IAM event names that should survive triage even without
# a severity field. BAU events (SELECT, LIST, DESCRIBE, routine file access) are
# intentionally excluded — they form single-source noise clusters at scale.
_CLOUD_SECURITY_EVENT_NAMES = frozenset({
    # CloudTrail privilege/secret abuse
    "assumerole", "assumerolewithsaml", "getsecretvalue", "getfederationtoken",
    "putbucketpolicy", "putrolepolicy", "deletebucketpolicy",
    # CloudTrail defense evasion
    "deletetrail", "stoprecording", "disablekey",
    "stopinstances", "terminateinstances", "deleteinstances",
    # Snowflake exfil verbs only (not BAU SELECT/DESCRIBE)
    "copy", "unload", "create stage", "copy into",
    # CloudTrail data-plane ops from external IPs (PutObject exfil staging)
    "putobject",
    # IAM recon that precedes credential abuse
    "getcalleridentity", "gettoken",
    # Okta / Entra risk signals (BAU auth events excluded: via_mfa, policy.evaluate_sign_on)
    "user.session.access_admin_app", "user.account.lock",
    "user.mfa.factor.deactivate", "user.account.update_password",
    # M365 risk signals (mailboxlogin/filedownloaded excluded — fire on every BAU access)
    "filesharinginfected",
    "searchqueryinitiatedshareddocument",
    # M365/Exchange high-risk IAM operations
    "new-inboxrule", "set-inboxrule", "disable-inboxrule",
    "add-mailboxpermission", "set-mailboxautoreply",
    # External send surfaced by Exchange audit
    "send",
})

_LOW_NOISE_SOURCE_TYPES = frozenset({"cloud", "iam", "email", "remote"})


_HIGH_SEVERITY_FACTORS = frozenset({
    'email:inbox_rule_external_forward',
    'email:T1114.003_inbox_rule',
    'data:sensitive_file_access',
    'endpoint:T1003.001_lsass_dump',
    'endpoint:T1021.001_rdp_lateral',
    'identity:priv_escalation',
    'exfil:cumulative_bytes_anomaly',
    'exfil:cumulative_cloud_bytes_anomaly',
    'endpoint:wmi_lateral_exec',
    'storyline:mstsc_suspicious_parent',
    'endpoint:T1021.001_rdp_lateral',
})

_CRITICAL_SEVERITY_FACTORS = frozenset({
    'endpoint:ebpf_rootkit',
    'iam:golden_ticket',
    'iam:kerberoasting',
    'exfil:bulk_download_finance',
    'endpoint:T1003.001_lsass_dump',
    'data_exfiltration_rclone',
    'data_exfiltration_snowflake',
})


def _score_async_ingest_row(raw: dict, normalized: dict) -> float:
    # Read severity from normalized _severity first (post-normalization field),
    # then fall back to raw source fields.  Capitalized 'Severity' covers M365.
    sev = str(
        normalized.get("_severity") or
        raw.get("severity") or raw.get("Severity") or
        raw.get("risk_level") or raw.get("alert_severity") or
        ""
    ).lower()
    score = {
        "critical": 0.95,
        "high": 0.75,
        "medium": 0.35,
        "low": 0.10,
        "info": 0.03,
        "informational": 0.03,
    }.get(sev, 0.05)

    # OAuth illicit-consent grant (excessive scopes + offline persistence) is a primary
    # intrusion ENTRY POINT — a single, individually-low-volume event. It must survive
    # triage filtering so it clusters with the actor's later activity and is narrated as
    # "how they got in". (Set by streaming_ingest._normalize_iam.)
    if normalized.get("oauth_consent_excessive") or raw.get("oauth_consent_excessive"):
        score = max(score, 0.85)

    # Elevate security-relevant cloud/IAM events above the triage threshold.
    # BAU events (SELECT queries, ListBuckets, routine file access) are NOT
    # elevated — they form single-source noise clusters at scale.
    source_type = str(normalized.get("_source_type") or normalized.get("source_type") or "").lower()
    if source_type in _LOW_NOISE_SOURCE_TYPES:
        event_name_lower = str(
            normalized.get("event_name") or raw.get("eventName") or
            raw.get("event_type") or raw.get("query_type") or ""
        ).lower()
        if any(k in event_name_lower for k in _CLOUD_SECURITY_EVENT_NAMES):
            score = max(score, 0.20)

    try:
        text = json.dumps(raw, default=str).lower()
    except Exception:
        text = str(raw).lower()
    for term in _HIGH_SIGNAL_TERMS:
        if term in text:
            score = max(score, 0.65)
            break

    # Elevate cloud events originating from external (non-RFC1918) IPs.
    # BAU cloud ops come from internal IPs; external-origin data-plane ops
    # (e.g. PutObject from attacker IP) are anomalous and breach-relevant.
    if source_type in _LOW_NOISE_SOURCE_TYPES and score < 0.20:
        _src_ip = str(normalized.get("src_ip") or "").strip()
        if _src_ip and not _src_ip.startswith(("10.", "172.", "192.168.", "127.", "0.")):
            try:
                import ipaddress as _ipa
                if not _ipa.ip_address(_src_ip).is_private:
                    score = max(score, 0.20)
            except (ValueError, TypeError):
                pass
    event_name = str(raw.get("event_simpleName") or raw.get("event_name") or raw.get("eventName") or "").lower()
    if raw.get("alert_signature") or raw.get("detect_id") or any(t in event_name for t in ("detect", "rtrexecuted", "alert")):
        score = max(score, 0.25)

    # Elevate Windows Security (Kerberos/WinEvent) rows above triage threshold.
    # These have no severity field so default to 0.05, but are always security-relevant
    # in a breach assessment context. Filter high-volume BAU events (logon/logoff).
    _raw_src_type = str(raw.get("source_type") or normalized.get("source_type") or "")
    if _raw_src_type == "windows_security":
        _win_eid = str(
            raw.get("windows_event_id") or raw.get("event_id") or raw.get("EventID") or ""
        ).strip()
        # Security-relevant event IDs — exclude 4624/4634 (high-volume logon/logoff)
        _WIN_SECURITY_EIDS = {
            "4768", "4769", "4771",  # Kerberos TGT/TGS/failure
            "4625", "4648", "4672",  # logon failure, explicit logon, special privileges
            "4698", "4702",          # scheduled task created/modified
            "4776", "4778", "4779",  # NTLM auth, session reconnect/disconnect
            "4720", "4738", "4740",  # account create, change, lockout
            "4728", "4732", "4756",  # group membership changes (domain/local/universal)
        }
        if _win_eid in _WIN_SECURITY_EIDS:
            score = max(score, 0.20)
        # Further elevate RC4 downgrade (kerberoasting indicator).
        # KERBEROAST_EXCLUDE_SERVICES: comma-separated service names that legitimately
        # use RC4 (e.g. svc_jenkins) — suppresses false positives.
        _enc = str(raw.get("ticket_encryption") or raw.get("ticket_encryption_type") or "").strip()
        if _enc in ("0x17", "0x18") and _win_eid == "4769":
            _target_svc = str(
                raw.get("service_name") or raw.get("target_service_name") or
                raw.get("target_user_name") or raw.get("ServiceName") or ""
            ).strip().lower()
            _requester = str(
                raw.get("account_name") or raw.get("user") or raw.get("user_canonical") or ""
            ).strip().lower()
            _exclude_svcs = {
                s.strip().lower() for s in
                os.getenv("KERBEROAST_EXCLUDE_SERVICES", "").split(",") if s.strip()
            }
            if not (_exclude_svcs and (_target_svc in _exclude_svcs or _requester in _exclude_svcs)):
                score = max(score, 0.75)
    # Elevate sysmon endpoint rows for process-create events with suspicious parents/commands
    _sysmon_eid = str(raw.get("sysmon_event_id") or "").strip()
    if _sysmon_eid == "1" or raw.get("source_type") == "sysmon":
        _cmdline = str(raw.get("command_line") or "").lower()
        _parent = str(raw.get("parent_process") or "").lower()
        if any(t in _cmdline for t in ("-enc", "-encodedcommand", "invoke-expression", "downloadstring", "iex(")):
            score = max(score, 0.65)
        elif "wmiprvse.exe" in _parent or "powershell" in _parent:
            score = max(score, 0.20)
    try:
        # Only count bytes actually moved over the wire — not read-side scan metrics.
        # bytes_scanned / rows_produced are Snowflake query-plan stats, not exfil volume.
        bytes_moved = float(
            raw.get("bytes_sent")
            or raw.get("orig_bytes")
            or raw.get("bytes")
            or 0
        )
        if bytes_moved > 100_000_000:
            score = max(score, 0.55)
    except Exception:
        pass
    # P4 — SharePoint lookalike subdomain: martin-chen.sharepoint.com vs org tenant.
    # JANUSEC_ORG_TENANT_NAME env var identifies the org's legitimate tenant prefix.
    try:
        _org_tenant = os.getenv("JANUSEC_ORG_TENANT_NAME", "").strip().lower()
        _dst_h = str(
            raw.get("dst_host") or raw.get("resp_h") or raw.get("destination_host") or
            raw.get("domain") or raw.get("tls_sni") or
            normalized.get("dst_host") or normalized.get("resp_h") or
            normalized.get("domain") or normalized.get("tls_sni") or normalized.get("dst_ip") or ""
        ).strip().lower()
        if _org_tenant and ".sharepoint.com" in _dst_h:
            _sp_prefix = _dst_h.split(".sharepoint.com")[0].rsplit(".", 1)[-1]
            if _sp_prefix and _sp_prefix != _org_tenant:
                score = max(score, 0.55)
                normalized["_sharepoint_subdomain_mismatch"] = _sp_prefix
    except Exception:
        pass
    # ── Kerberos / Windows Security EventID fast-path ─────────────────────────
    # factor_tags are NOT available at Stage 1 (they're computed in Stage 5x).
    # Use raw event fields directly for known attack event patterns so the
    # triage_score and _severity are correct before DuckDB storage.
    _eid_s1 = str(
        normalized.get('windows_event_id') or raw.get('windows_event_id') or
        raw.get('WindowsEventId') or raw.get('EventID') or raw.get('event_id') or ''
    ).strip()
    _enc_s1 = str(normalized.get('ticket_encryption') or raw.get('ticket_encryption') or '').strip()
    _svc_s1 = str(normalized.get('service_name') or raw.get('service_name') or '').strip().lower()
    _pauth_s1 = str(normalized.get('pre_auth_type') or raw.get('pre_auth_type') or '').strip()
    _cmd_s1 = str(normalized.get('command_line') or raw.get('command_line') or '').lower()
    _proc_s1 = str(normalized.get('process_name') or raw.get('process_name') or '').lower()
    # Ticket options bitmask (4769/4770 field). Mimikatz golden ticket default = 0x60a10000.
    # PROXIABLE (0x20000000) is never legitimately set on service ticket requests from endpoints.
    _topts_s1_raw = str(
        normalized.get('ticket_options') or raw.get('ticket_options') or
        raw.get('TicketOptions') or raw.get('ticket_flags') or '0x0'
    ).strip().lower()
    try:
        _topts_s1 = int(_topts_s1_raw, 16) if _topts_s1_raw.startswith('0x') else int(_topts_s1_raw, 0)
    except (ValueError, TypeError):
        _topts_s1 = 0
    # Ticket lifetime field (hours). Mimikatz forges 10-year TGTs (87600 h). Legitimate max ~10 h.
    _tlife_s1_raw = str(
        normalized.get('ticket_lifetime_hours') or raw.get('ticket_lifetime_hours') or
        raw.get('TicketLifetimeHours') or raw.get('ticket_lifetime') or '0'
    ).strip()
    try:
        _tlife_s1 = float(_tlife_s1_raw)
    except (ValueError, TypeError):
        _tlife_s1 = 0.0
    # PROXIABLE + FORWARDABLE bits simultaneously = strong golden ticket indicator
    _GT_PROXIABLE_FLAG = 0x20000000
    _GT_FORWARDABLE_FLAG = 0x40000000
    _topts_gt_suspicious = bool(
        (_topts_s1 & _GT_PROXIABLE_FLAG) and (_topts_s1 & _GT_FORWARDABLE_FLAG)
    )
    # 10-year lifetime: > 86400 h (10 years = 87600 h, add small margin)
    _tlife_forged = _tlife_s1 > 86400

    if _eid_s1 in ('4769', '4768'):
        # 4769 + RC4 encryption (0x17/0x18) = kerberoasting
        if _eid_s1 == '4769' and _enc_s1 in ('0x17', '0x18', '23', '24'):
            score = max(score, 0.92)
            normalized.setdefault('_severity', 'critical')
        # 4769 targeting krbtgt = golden ticket (use-phase)
        elif _eid_s1 == '4769' and _svc_s1 == 'krbtgt':
            score = max(score, 0.92)
            normalized.setdefault('_severity', 'critical')
            # Sub-indicators that confirm forgery vs. legitimate krbtgt TGS
            _gt_subs: list[str] = []
            if _topts_gt_suspicious:
                _gt_subs.append(f"proxiable+forwardable_flags=0x{_topts_s1:08x}")
            if _tlife_forged:
                _gt_subs.append(f"forged_lifetime={_tlife_s1:.0f}h")
            if _gt_subs:
                normalized['_golden_ticket_subindicators'] = _gt_subs
                # Confirmed forged TGT — push toward 0.97
                score = max(score, 0.97)
        # 4768 + pre-auth disabled = AS-REP roasting
        elif _eid_s1 == '4768' and _pauth_s1 in ('0', '0x0'):
            score = max(score, 0.92)
            normalized.setdefault('_severity', 'critical')
        else:
            # Elevated ticket options still suspicious even without krbtgt target
            if _topts_gt_suspicious:
                score = max(score, 0.85)
                normalized.setdefault('_severity', 'high')
                normalized['_golden_ticket_subindicators'] = [f"proxiable+forwardable_flags=0x{_topts_s1:08x}"]
            else:
                score = max(score, 0.70)
                normalized.setdefault('_severity', 'high')
    elif _eid_s1 in ('4771', '4776', '4648'):
        score = max(score, 0.70)
        normalized.setdefault('_severity', 'high')
    elif _eid_s1 in ('7045', '4104'):
        # Service install / PowerShell script block logging
        score = max(score, 0.70)
        normalized.setdefault('_severity', 'high')

    # LOLbin / suspicious process detection from command_line / process_name
    _LOLBIN_PROCS = frozenset({
        'mshta.exe', 'certutil.exe', 'bitsadmin.exe', 'regsvr32.exe',
        'msiexec.exe', 'wmic.exe', 'cscript.exe', 'wscript.exe',
        'installutil.exe', 'msbuild.exe', 'cmstp.exe', 'odbcconf.exe',
    })
    _LOLBIN_CMD_PATTERNS = (
        'invoke-expression', 'iex ', 'downloadstring', 'downloadfile',
        'net.webclient', 'encodedcommand', '-enc ', 'frombase64string',
        'comsvcs', 'rundll32', 'powershell -', '/c whoami', 'cmd /c',
    )
    if _proc_s1 in _LOLBIN_PROCS or any(p in _cmd_s1 for p in _LOLBIN_CMD_PATTERNS):
        score = max(score, 0.70)
        normalized.setdefault('_severity', 'high')

    # ── Factor-tag based severity elevation ───────────────────────────────────
    # NOTE: factor_tags are set in Stage 5x, AFTER this function runs, so this
    # check is only effective for rows that were pre-tagged by an earlier pass.
    _row_factors = set(normalized.get('factor_tags') or [])
    if _row_factors & _CRITICAL_SEVERITY_FACTORS:
        score = max(score, 0.90)
        if not normalized.get('_severity'):
            normalized['_severity'] = 'critical'
    elif _row_factors & _HIGH_SEVERITY_FACTORS:
        score = max(score, 0.70)
        if not normalized.get('_severity'):
            normalized['_severity'] = 'high'

    return float(max(0.0, min(1.0, score)))


# ── Stage 1 shared constants (used by _parse_file_to_store) ───────────────────
_SENSITIVE_PATH_TOKENS_STAGE1: tuple[str, ...] = (
    "payroll", "acquisition", "merger", "novabridge", "ip-schedule",
    "infra-map", "capex", "q1-projections", "ceo", "board",
    "ma-document", "merger-ip", "novabridge-acquisition",
    "critical-infra", "critical_infra",
)
_CORP_TLDS: tuple[str, ...] = (".com.au", ".gov.au", ".net.au", ".org.au")


def _parse_file_to_store(
    path: str,
    filename: str,
    file_lane: str,
    row_offset: int,
    assessment_id: str,
    store,
) -> int:
    """Parse + normalize + tag one file and flush rows to DuckDB in batches.

    Runs synchronously inside asyncio.to_thread() so large NDJSON / CSV files
    do not block the event loop.  Returns the number of rows stored.
    """
    from src.core.ingest.file_parser import parse_file as _pf

    batch: list[dict] = []
    local_count = 0
    try:
        for raw_row in _pf(path, filename=filename):
            norm = _normalize_ingest_row(raw_row, row_offset + local_count)
            norm.setdefault("_lane", file_lane)

            # file-sensitivity tagging
            _obj = str(
                norm.get("ObjectId") or norm.get("object_id") or
                norm.get("file_path") or norm.get("resource") or ""
            ).lower()
            if any(tok in _obj for tok in _SENSITIVE_PATH_TOKENS_STAGE1):
                norm.setdefault("_sensitivity", "high")
                norm["triage_score"] = max(norm.get("triage_score") or 0.0, 0.65)

            # external_recipient_domain tagging for email rows
            for _rec_fld in ("Recipients", "recipients"):
                _recs = norm.get(_rec_fld)
                if not _recs:
                    continue
                if isinstance(_recs, str):
                    _recs = [_recs]
                for _rec in _recs[:4]:
                    _dom = str(_rec).split("@")[-1].lower().strip() if "@" in str(_rec) else ""
                    if _dom and "." in _dom and not any(_dom.endswith(t) for t in _CORP_TLDS):
                        norm.setdefault("external_recipient_domain", _dom)
                        norm["triage_score"] = max(norm.get("triage_score") or 0.0, 0.25)
                        break
            _fwd = str(norm.get("ForwardingSmtpAddress") or norm.get("forwarding_smtp") or "").strip()
            if "@" in _fwd:
                _fdom = _fwd.split("@")[-1].lower()
                if not any(_fdom.endswith(t) for t in _CORP_TLDS):
                    norm.setdefault("external_recipient_domain", _fdom)
                    norm["triage_score"] = max(norm.get("triage_score") or 0.0, 0.65)

            batch.append(norm)
            local_count += 1
            if len(batch) >= PARSE_BATCH_SIZE:
                store.persist_row_batch(assessment_id, batch)
                batch = []
    except Exception as exc:
        logger.warning("parse failed for %s in job %s: %s", filename, assessment_id, exc)
    if batch:
        store.persist_row_batch(assessment_id, batch)
    return local_count


def _collect_lane_factor_tags(rows: list[dict]) -> dict[int, list[str]]:
    """Lightweight synchronous scan of normalized rows for detectable hunt-lane patterns.

    Returns a dict mapping row_index (int) -> list of factor strings.
    This mirrors the factor IDs emitted by the live hunt lanes
    (email_bec, user_session_fusion, endpoint_storyline, data_insider)
    so that assessment clusters can carry ``factor_tags`` without running
    the full async lane infrastructure.
    """
    from collections import defaultdict
    result: dict[int, list[str]] = defaultdict(list)

    # Per-user events for impossible-travel detection: user -> [(ts, country, ridx)]
    user_events: dict[str, list[tuple[float, str, int]]] = defaultdict(list)

    # MITRE technique ID → factor string mappings (common breach patterns)
    _MITRE_FACTORS: dict[str, str] = {
        "T1003": "endpoint:T1003_credential_dump",
        "T1003.001": "endpoint:T1003.001_lsass_dump",
        "T1110": "endpoint:T1110_brute_force",
        "T1110.003": "endpoint:T1110.003_password_spray",
        "T1078": "endpoint:T1078_valid_accounts",
        "T1021.001": "endpoint:T1021.001_rdp_lateral",
        "T1071.001": "endpoint:T1071.001_web_c2",
        "T1071.004": "endpoint:T1071.004_dns_c2",
        "T1041": "endpoint:T1041_exfil_c2",
        "T1048": "endpoint:T1048_exfil_alt_channel",
        "T1048.003": "endpoint:T1048.003_exfil_unenc",
        "T1114.003": "email:T1114.003_inbox_rule",
        "T1550.002": "endpoint:T1550.002_pass_the_hash",
        "T1059.001": "endpoint:T1059.001_powershell",
        "T1204.002": "endpoint:T1204.002_malicious_attachment",
        "T1564.001": "endpoint:T1564.001_hidden_file",
        "T1046": "endpoint:T1046_port_scan",
    }

    for row in rows:
        _ri = row.get("row_index")
        if _ri is None:
            continue
        try:
            ridx = int(float(_ri))
        except (TypeError, ValueError):
            continue

        # ── MITRE technique direct mapping ───────────────────────────────────
        if row.get("_sharepoint_subdomain_mismatch"):
            result[ridx].append("network:sharepoint_subdomain_mismatch")
            result[ridx].append("cloud:sharepoint_lookalike")

        mitre_id = str(row.get("mitre_technique") or "").strip()
        if mitre_id:
            # Try full match first, then prefix (T1003.001 → also add T1003)
            if mitre_id in _MITRE_FACTORS:
                result[ridx].append(_MITRE_FACTORS[mitre_id])
            parent_id = mitre_id.split(".")[0]
            if parent_id != mitre_id and parent_id in _MITRE_FACTORS:
                result[ridx].append(_MITRE_FACTORS[parent_id])

        # ── email_bec: inbox rule with external forwarding ──────────────────
        ev_name = str(
            row.get("event_name") or row.get("EventName") or
            row.get("operation") or row.get("Operation") or ""
        ).lower().replace("-", "").replace("_", "")
        if "inboxrule" in ev_name:
            fwd = str(
                row.get("ForwardingSmtpAddress") or row.get("forwarding_smtp") or
                row.get("external_recipient_domain") or ""
            ).strip()
            if fwd and ("@" in fwd or "." in fwd):
                result[ridx].append("email:T1114.003_inbox_rule")
                result[ridx].append("email:inbox_rule_external_forward")

        # ── data_insider: sensitive file access ─────────────────────────────
        if row.get("_sensitivity") == "high":
            result[ridx].append("data:sensitive_file_access")

        # ── endpoint_storyline: LSASS access (T1003.001) ────────────────────
        # Check both process_name (CrowdStrike/Sysmon) and parent_process (XLSX/KAPE)
        proc = str(
            row.get("process_name") or row.get("TargetProcessName") or
            row.get("image") or row.get("process") or ""
        ).lower()
        parent = str(
            row.get("parent_process_name") or row.get("ParentProcessName") or
            row.get("parent_process") or ""
        ).lower()
        if "lsass" in proc or ("lsass" in parent and mitre_id.startswith("T1003")):
            result[ridx].append("storyline:lsass_access")
            result[ridx].append("endpoint:T1003.001_lsass_dump")

        # ── endpoint_storyline: mstsc from suspicious parent ────────────────
        _MSTSC_BENIGN = {"explorer.exe", "taskmgr.exe", "rdpclip.exe", ""}
        if proc.endswith("mstsc.exe") and parent not in _MSTSC_BENIGN:
            result[ridx].append("storyline:mstsc_suspicious_parent")
            result[ridx].append("endpoint:T1021.001_rdp_lateral")

        # ── user_session_fusion: collect for impossible-travel check ────────
        cmdline = str(row.get("command_line") or row.get("CommandLine") or row.get("cmdline") or "").lower()
        if (
            ("wmic" in proc or "wmic" in cmdline)
            and "/node:" in cmdline
            and "process call create" in cmdline
        ) or ("wmiprvse.exe" in parent and ("-enc" in cmdline or "encodedcommand" in cmdline)):
            result[ridx].append("endpoint:wmi_lateral_exec")

        user = str(row.get("user") or row.get("user_canonical") or "").strip()
        country = str(row.get("src_country") or "").strip()
        if user and len(country) == 2 and country.isalpha():
            ts_raw = str(
                row.get("event_time") or row.get("timestamp") or
                row.get("date_utc") or row.get("eventTime") or "0"
            )
            try:
                import datetime as _dt
                ts = _dt.datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).timestamp()
            except Exception:
                try:
                    ts = float(ts_raw)
                except Exception:
                    ts = 0.0
            user_events[user].append((ts, country.upper(), ridx))

    # ── user_session_fusion: impossible travel per user ──────────────────────
    for user, events in user_events.items():
        sorted_evs = sorted(events, key=lambda x: x[0])
        last_country: str | None = None
        for _ts, country, ridx in sorted_evs:
            if last_country and country != last_country:
                result[ridx].append("fusion:impossible_travel")
                result[ridx].append(f"fusion:impossible_travel_{last_country}_to_{country}")
            last_country = country

    return dict(result)


# ── Per-job pipeline ───────────────────────────────────────────────────────────

async def run_assessment_pipeline(
    assessment_id: str,
    org: str,
    file_paths: list[tuple[str, str]],  # [(saved_path, original_filename), ...]
    *,
    progress_fn: ProgressFn = _noop_progress,
    auto_llm: bool = False,
) -> str:
    """Full ingest pipeline for one assessment job.  Returns assessment_id."""
    from src.core.ingest import store as _store

    def _progress(stage: str, pct: int, label: str) -> None:
        try:
            _store.update_job(
                assessment_id,
                status="running",
                stage=stage,
                percent=pct,
                stage_label=label,
            )
        except Exception:
            pass
        progress_fn(assessment_id, stage, pct, label)

    try:
        # Guard: if the job was cancelled before we got here, bail out.
        _pre_status = (_store.get_job(assessment_id) or {}).get("status", "")
        if _pre_status == "cancelled":
            logger.info("assessment pipeline skipped (cancelled): %s", assessment_id)
            return assessment_id
        _store.update_job(assessment_id, status="running", stage="parsing", percent=0, stage_label="Parsing files")

        # ── Stage 1: parse and store all rows ────────────────────────────────
        total_rows = 0
        quarantined_files: list[dict] = []
        context_files: list[dict] = []
        telemetry_files: list[str] = []

        from src.core.ingest.input_classifier import LANE_TELEMETRY_EVIDENCE, LANE_EVALUATION_ANSWER_KEY

        for file_idx, (path, filename) in enumerate(file_paths):
            file_pct = int(30 * (file_idx / max(len(file_paths), 1)))
            _progress("parsing", file_pct, f"Parsing {filename}")

            # Classify the file lane before parsing so rows can carry provenance.
            file_lane = LANE_TELEMETRY_EVIDENCE
            if filename.lower().endswith(".xlsx"):
                try:
                    from src.core.ingest.input_classifier import classify_xlsx_path
                    lane_result = classify_xlsx_path(path, filename=filename)
                    file_lane = lane_result.get("lane", LANE_TELEMETRY_EVIDENCE)
                    if file_lane == LANE_EVALUATION_ANSWER_KEY:
                        quarantined_files.append({"filename": filename, "lane": file_lane, "reason": lane_result.get("reason", "")})
                        logger.info("assessment %s: quarantined %s as %s", assessment_id, filename, file_lane)
                        continue
                    if file_lane == "business_context":
                        context_files.append({"filename": filename, "lane": file_lane})
                except Exception as exc:
                    logger.warning("lane classification failed for %s: %s", filename, exc)

            if file_lane == LANE_TELEMETRY_EVIDENCE:
                telemetry_files.append(filename)

            # ── Stage 1b: parse + normalize + tag in a thread ────────────────
            # Running in asyncio.to_thread() means large NDJSON/CSV files (e.g.
            # Meridian's 11 MB corpus) do not block the event loop: DuckDB writes
            # still hold _lock sequentially, but I/O and JSON parsing happen
            # in a worker thread, freeing the loop for timeouts and SSE ticks.
            file_rows = await asyncio.to_thread(
                _parse_file_to_store, path, filename, file_lane, total_rows, assessment_id, _store,
            )
            total_rows += file_rows
            _progress("parsing", file_pct, f"Parsed {total_rows:,} rows ({filename})")

        _store.update_job(assessment_id, row_count=total_rows)
        _progress("normalizing", 32, f"Stored {total_rows:,} rows — preparing clustering")

        if total_rows == 0:
            _store.update_job(assessment_id, status="failed", error="No rows parsed from uploaded files")
            return assessment_id

        # ── Stage 2: load rows for clustering (triage pre-filter) ─────────────
        # Critical addition #1: only pass rows with triage_score >= threshold
        # to the O(n²) clustering engine.  Noise rows stay in the DB and appear
        # in the final evidence_rows list but don't participate in clustering.
        _progress("clustering", 35, "Loading high-signal rows for clustering")

        filtered_rows = await asyncio.to_thread(
            _store.load_rows,
            assessment_id,
            min_triage=TRIAGE_MIN_FOR_CLUSTER,
            limit=CLUSTER_ROW_CAP,
        )
        evidence_preview = await asyncio.to_thread(
            _store.load_rows,
            assessment_id,
            min_triage=0.0,
            limit=ASSESSMENT_EVIDENCE_PREVIEW_CAP,
        )

        logger.info(
            "assessment %s: %d total rows, %d above triage threshold %.2f (cap %d)",
            assessment_id, total_rows, len(filtered_rows), TRIAGE_MIN_FOR_CLUSTER, CLUSTER_ROW_CAP,
        )

        # ── Stage 2b: user-IP /16 anomaly pre-tagging ──────────────────────────
        try:
            from collections import defaultdict as _dd
            _user_ip16: dict[str, set] = _dd(set)
            for _r2b in filtered_rows:
                _u2b = str(_r2b.get("user_canonical") or _r2b.get("user") or "").strip()
                _ip2b = str(_r2b.get("src_ip") or "").strip()
                if not _u2b or not _ip2b or _u2b in ("-", "n/a", ""):
                    continue
                parts = _ip2b.split(".")
                if len(parts) >= 2:
                    _user_ip16[_u2b].add(f"{parts[0]}.{parts[1]}")
            for _u2b, _blocks in _user_ip16.items():
                _others: set = set()
                for _ou, _ob in _user_ip16.items():
                    if _ou != _u2b:
                        _others.update(_ob)
                _personal = _blocks - _others
                if _personal:
                    _tagged = 0
                    for _r2b in filtered_rows:
                        if str(_r2b.get("user_canonical") or _r2b.get("user") or "") == _u2b:
                            _ip_r = str(_r2b.get("src_ip") or "").strip()
                            _blk_r = ".".join(_ip_r.split(".")[:2]) if "." in _ip_r else ""
                            if _blk_r in _personal:
                                if not _r2b.get("_anomaly"):
                                    _r2b["_anomaly"] = "user_ip_drift"
                                _r2b["triage_score"] = max(float(_r2b.get("triage_score") or 0.0), 0.65)
                                _tagged += 1
                    if _tagged:
                        logger.info(
                            "assessment %s: user %s on anomalous /16s %s — tagged %d rows user_ip_drift",
                            assessment_id, _u2b, _personal, _tagged,
                        )
        except Exception as _exc2b:
            logger.debug("Stage 2b user-IP anomaly tagging failed for %s: %s", assessment_id, _exc2b)

        # ── Stage 2c: GeoIP / ASN inline enrichment ───────────────────────────
        # Tag every row with a public src_ip / dst_ip with structured asn,
        # asn_name, country fields. This feeds: (a) the executive summary's
        # "attacker pivoted from AS4134 (CN)" sentence, (b) the proposed_actions
        # "Block egress to AS<X>" recommendation, (c) the breach.js infra panel
        # (replaces hardcoded AS209132 placeholder), and (d) downstream
        # geopolitical-risk scoring (CN/RU/KP/IR triage boost).
        try:
            from src.live.asn_lookup import lookup_ip_meta, is_high_risk_country
            _ip_cache: dict[str, dict] = {}
            _enriched_count = 0
            _high_risk_count = 0
            _high_risk_countries: set[str] = set()
            for _r2c in filtered_rows:
                for _ip_fld in ("src_ip", "dst_ip", "external_ip", "client_ip", "remote_ip"):
                    _ip2c = str(_r2c.get(_ip_fld) or "").strip()
                    if not _ip2c or _ip2c in ("-", "0.0.0.0", "::") or _ip2c.startswith("10.") or _ip2c.startswith("192.168."):
                        continue
                    if _ip2c not in _ip_cache:
                        try:
                            _ip_cache[_ip2c] = lookup_ip_meta(_ip2c) or {}
                        except Exception:
                            _ip_cache[_ip2c] = {}
                    _meta = _ip_cache[_ip2c]
                    if _meta:
                        # Per-row enrichment fields (src vs dst variants for clarity)
                        _prefix = "src_" if _ip_fld == "src_ip" else (
                            "dst_" if _ip_fld == "dst_ip" else "")
                        if _meta.get("asn"):
                            _r2c.setdefault(f"{_prefix}asn", _meta["asn"])
                            _r2c.setdefault("asn", _meta["asn"])  # convenience top-level
                        if _meta.get("asn_name"):
                            _r2c.setdefault(f"{_prefix}asn_name", _meta["asn_name"])
                        if _meta.get("country"):
                            _r2c.setdefault(f"{_prefix}country", _meta["country"])
                            _r2c.setdefault("country", _meta["country"])
                            if is_high_risk_country(_meta["country"]):
                                _r2c.setdefault("_geopolitical_risk", "high")
                                _r2c["triage_score"] = max(
                                    float(_r2c.get("triage_score") or 0.0), 0.7,
                                )
                                _high_risk_count += 1
                                _high_risk_countries.add(_meta["country"])
                        _enriched_count += 1
                        # Only enrich one IP per row to avoid double-counting
                        break
            if _enriched_count:
                logger.info(
                    "Stage 2c: GeoIP/ASN enriched %d rows (%d unique IPs, %d high-risk in %s)",
                    _enriched_count, len(_ip_cache), _high_risk_count,
                    sorted(_high_risk_countries) if _high_risk_countries else "none",
                )
        except Exception as _exc2c:
            logger.debug("Stage 2c GeoIP/ASN enrichment failed for %s: %s", assessment_id, _exc2c)

        _progress("clustering", 40, f"Clustering {len(filtered_rows):,} high-signal rows")

        # ── Stage 3: build assessment shell and run hydration ─────────────────
        source_counts = await asyncio.to_thread(_store.source_counts, assessment_id)
        assessment: dict[str, Any] = {
            "assessment_id": assessment_id,
            "org": org,
            "rows": filtered_rows,            # clustering input
            "all_rows": evidence_preview,
            "rows_processed": total_rows,
            "uploaded_row_count": total_rows,
            "total_rows_uploaded": total_rows,
            "source_count": len(source_counts),
            "source_counts": source_counts,
            "created_at": datetime.datetime.utcnow().isoformat() + "Z",
            "upload_provenance": {"source": "async_ingest", "file_count": len(file_paths), "total_rows": total_rows},
            "evidence_store": {
                "backend": "duckdb",
                "row_count": total_rows,
                "preview_limit": ASSESSMENT_EVIDENCE_PREVIEW_CAP,
                "evidence_url": f"/api/v1/assessments/{assessment_id}/evidence",
                "source_counts": source_counts,
            },
            "options": {"auto_llm": False, "mode": "offline_workbook"},
            "evidence_policy": {
                "policy_version": "1.0",
                "allowed_finding_lanes": ["telemetry_evidence"],
                "telemetry_inputs": telemetry_files,
                "context_inputs": [f["filename"] for f in context_files],
                "quarantined_inputs": quarantined_files,
            },
            # Version stamps — used by consumers to detect stale cached outputs.
            "normalizer_version": None,  # stamped below after lazy import
            "cluster_merge_version": None,
            "clustering_mode": None,     # typed_cluster_merge | failed
            "fallback_used": False,
            "requires_reingest": False,
            "cluster_diagnostics": {},
        }
        try:
            from src.pipeline.streaming_ingest import _NORMALIZER_VERSION
            assessment["normalizer_version"] = _NORMALIZER_VERSION
        except Exception:
            pass
        try:
            from src.core.ingest.cluster_merge import _CLUSTER_MERGE_VERSION
            assessment["cluster_merge_version"] = _CLUSTER_MERGE_VERSION
        except Exception:
            pass

        raw_clusters: list[dict[str, Any]] = []
        if os.getenv("JANUSEC_ASYNC_LEGACY_HYDRATE", "0").lower() in {"1", "true", "yes"}:
            try:
                from src.api.deep_analyze_endpoints import _hydrate_assessment_semantics
                await asyncio.to_thread(_hydrate_assessment_semantics, assessment)
            except Exception as exc:
                logger.warning("_hydrate_assessment_semantics failed for %s: %s", assessment_id, exc)
            raw_clusters = list(assessment.get("correlation_clusters") or [])
        else:
            _progress("clustering", 55, "Building SQL pivot groups")
            pivot_groups = await asyncio.to_thread(_store.entity_pivot_groups, assessment_id, TRIAGE_MIN_FOR_CLUSTER)

            # Keep raw pivot groups as audit inventory (one entry per shared entity).
            raw_pivot_clusters = [
                {
                    "cluster_id": f"pivot-{n}",
                    "lead_description": f"Shared pivot {pivot}",
                    "reason_summary": f"{len(refs)} rows share {pivot}",
                    "row_refs": refs,
                    "row_count": len(refs),
                    "confidence": min(0.95, 0.35 + (len(refs) / 200.0)),
                }
                for n, (pivot, refs) in enumerate(list(pivot_groups.items())[:200], start=1)
            ]
            assessment["sql_pivot_group_count"] = len(pivot_groups)
            assessment["raw_correlation_clusters"] = raw_pivot_clusters

            # Transitive campaign merge: evidence-bound, time-windowed union-find.
            # Produces analysis_clusters with cluster_kind / phases instead of
            # 200 disconnected pivot-per-row fragments.
            # Fail-closed: if cluster_merge raises, set requires_reingest instead of
            # silently promoting raw pivot fragments to production clusters.
            try:
                from src.core.ingest.cluster_merge import transitive_merge_clusters
                from src.core.entity_resolver import resolve_entities
                # Entity resolution: backfill host->owner so host-only telemetry (network
                # exfil, endpoint) stitches to the identity campaign instead of fragmenting
                # into no-user clusters. This is what lets the cumulative exfil attach to
                # the actor (proven against the VESPER ground-truth gate).
                await asyncio.to_thread(resolve_entities, filtered_rows)
                _progress("clustering", 60, "Transitive campaign merge")
                _diag: dict[str, Any] = {}
                analysis_clusters = await asyncio.to_thread(
                    transitive_merge_clusters,
                    None,          # let cluster_merge build scope-qualified pivots from rows
                    filtered_rows,
                    diagnostics_out=_diag,
                )
                # Split isolated (single-source unclassified) from actionable clusters.
                actionable = [c for c in analysis_clusters if not c.get("_isolated")]
                isolated_noise = [c for c in analysis_clusters if c.get("_isolated")]
                raw_clusters = actionable
                assessment["clustering_mode"] = "typed_cluster_merge"
                assessment["cluster_diagnostics"] = _diag
                assessment["isolated_count"] = len(isolated_noise)
                assessment["isolated_clusters"] = isolated_noise  # kept for audit
                logger.info(
                    "assessment %s: cluster_merge → %d actionable + %d isolated from %d raw pivots "
                    "(stale_rows=%d singleton_drops=%d)",
                    assessment_id, len(actionable), len(isolated_noise), len(pivot_groups),
                    _diag.get("stale_rows", 0), _diag.get("singleton_drop_count", 0),
                )
                if _diag.get("stale_rows", 0) > 0:
                    stale_pct = round(_diag["stale_rows"] / max(len(filtered_rows), 1) * 100, 1)
                    if stale_pct >= 50:
                        # Majority of clustered rows are stale — mark for reingest
                        assessment["requires_reingest"] = True
                        logger.warning(
                            "assessment %s: %.1f%% of clustering rows are stale (no canonical fields) — requires_reingest=True",
                            assessment_id, stale_pct,
                        )
            except Exception as exc:
                logger.error(
                    "cluster_merge failed for %s — setting requires_reingest=True: %s",
                    assessment_id, exc,
                )
                assessment["clustering_mode"] = "failed"
                assessment["fallback_used"] = True
                assessment["requires_reingest"] = True
                raw_clusters = []  # fail-closed: no production clusters from broken merge

            assessment["correlation_clusters"] = raw_clusters

        clusters = raw_clusters
        _store.update_job(assessment_id, cluster_count=len(clusters))
        _progress("clustering", 65, f"Found {len(clusters)} correlation clusters")

        # ── Stage 4: offline workbook merge ───────────────────────────────────
        if os.getenv("JANUSEC_ASYNC_LEGACY_HYDRATE", "0").lower() in {"1", "true", "yes"}:
            _progress("reasoning", 68, "Running enrichment cases and offline merge")
            try:
                from src.api.deep_analyze_endpoints import _merge_offline_workbook_assessment
                assessment = await asyncio.to_thread(
                    _merge_offline_workbook_assessment,
                    assessment,
                    filtered_rows,
                    {},
                    {"mode": "offline_workbook"},
                    assessment_id=assessment_id,
                    org=org,
                    auto_llm=False,
                )
            except Exception as exc:
                logger.debug("offline workbook merge skipped for %s: %s", assessment_id, exc)

        # ── Stage 5: structured LLM narratives (top-N clusters only) ─────────
        # Critical additions #2 and #3: evidence budget + structured JSON schema.
        # We do NOT run LLM on every row — only on the top-N clusters after
        # deterministic clustering completes.  This bounds LLM cost regardless
        # of dataset size.
        try:
            from src.core.ingest.threat_case_builder import build_threat_cases
            raw_clusters = list(assessment.get("correlation_clusters") or clusters or [])
            layers = build_threat_cases(raw_clusters, filtered_rows)
            assessment["raw_correlation_clusters"] = layers.get("raw_correlation_clusters") or raw_clusters
            assessment["analysis_clusters"] = layers.get("analysis_clusters") or raw_clusters
            assessment["threat_cases"] = layers.get("threat_cases") or []
            assessment["correlation_clusters"] = assessment["analysis_clusters"]
            clusters = assessment["analysis_clusters"]
            _store.update_job(assessment_id, cluster_count=len(clusters))
            _progress("clustering", 70, f"Classified {len(clusters)} analysis clusters")
        except Exception as exc:
            logger.warning("threat case layering failed for %s: %s", assessment_id, exc)
            clusters = assessment.get("correlation_clusters") or clusters

        # ── Stage 5b: deterministic DREAD/SABSA enrichment ───────────────────
        # Stores into tier1_prefill['dread_narrative'] — the exact structure the
        # frontend reads: {fragments, fill_rate, sabsa_attributes, sabsa_coda_draft}.
        # Also writes flat aliases (dread_fragments, sabsa_coda_draft) for the
        # compact exec-summary path in breach.js._compactExecSummary.
        # Result: cards show real evidence text immediately, before LLM fires.
        # "source: Legacy fallback" only appears if NO fragments at all are present.
        try:
            from src.prefill.dread_fragments import build_dread_narrative, fragments_fill_rate
            from src.prefill.sabsa_coda import build_sabsa_coda, derive_breached_attributes
            _row_lookup: dict[int, dict] = {}
            for _r5b in filtered_rows:
                _ri5b = _r5b.get('row_index')
                if _ri5b is not None:
                    try:
                        _row_lookup[int(float(_ri5b))] = _r5b
                    except (TypeError, ValueError):
                        pass
            _dread_ok = 0
            for _cl in clusters:
                if not _is_breach_cluster(_cl):
                    continue
                _cl_rows = []
                for _ref5b in (_cl.get('row_refs') or []):
                    try:
                        _k5b = int(float(_ref5b))
                        if _k5b in _row_lookup:
                            _cl_rows.append(_row_lookup[_k5b])
                    except (TypeError, ValueError):
                        pass
                if not _cl_rows:
                    continue
                _t1 = _cl.setdefault('tier1_prefill', {})
                # Skip if LLM has already produced a higher-quality render
                if _t1.get('dread_narrative', {}).get('fill_rate', 0) >= 0.60:
                    continue
                try:
                    _frags = build_dread_narrative(_cl_rows, _cl, _t1)
                    _fill = round(fragments_fill_rate(_frags), 2)
                    _attrs = derive_breached_attributes(_frags)
                    _coda = build_sabsa_coda(_frags, _attrs)
                    # Primary path: what the frontend _dreadInfo() reads
                    _t1['dread_narrative'] = {
                        'fragments':        _frags,
                        'fill_rate':        _fill,
                        'sabsa_attributes': _attrs,
                        'sabsa_coda_draft': _coda,
                    }
                    # Flat aliases for _compactExecSummary / exec-summary panel
                    _t1['dread_fragments'] = _frags
                    if _coda:
                        _t1['sabsa_coda_draft'] = _coda
                    _dread_ok += 1
                except Exception as _dread_err:
                    logger.debug("dread enrichment failed for cluster %s: %s", _cl.get('cluster_id'), _dread_err)
            _progress("reasoning", 70, f"DREAD/SABSA enrichment complete ({_dread_ok} clusters)")
        except Exception as exc:
            logger.warning("dread/sabsa enrichment stage failed for %s: %s", assessment_id, exc)

        # ── Stage 5c: deterministic cluster intelligence enrichments (Blocks 2+3) ─
        # event_chain_summary, kill_chain_summary, adversarial_sequence, DREAD numeric,
        # Diamond model, PASTA summary, known/unknown entity split.
        # Runs synchronously for ALL breach clusters — no LLM required.
        try:
            from src.core.tier1_prefill.prefill_engine import _enrich_cluster_intelligence
            _row_lookup_ei: dict[int, dict] = {}
            for _r5c in filtered_rows:
                _ri5c = _r5c.get('row_index')
                if _ri5c is not None:
                    try:
                        _row_lookup_ei[int(float(_ri5c))] = _r5c
                    except (TypeError, ValueError):
                        pass
            _ei_ok = 0
            for _cl in clusters:
                if not _is_breach_cluster(_cl):
                    continue
                _cl_rows_ei = []
                for _ref5c in (_cl.get('row_refs') or []):
                    try:
                        _k5c = int(float(_ref5c))
                        if _k5c in _row_lookup_ei:
                            _cl_rows_ei.append(_row_lookup_ei[_k5c])
                    except (TypeError, ValueError):
                        pass
                _t1_ei = _cl.setdefault('tier1_prefill', {})
                try:
                    _enrich_cluster_intelligence(_t1_ei, _cl, _cl_rows_ei)
                    _derive_santos_tier2_aliases(_cl, _cl_rows_ei)
                    _sync_cluster_prefill_aliases(_cl)
                    _ei_ok += 1
                except Exception as _ei_err:
                    logger.warning('cluster intelligence enrichment failed for %s: %s', _cl.get('cluster_id'), _ei_err, exc_info=True)
            logger.info('Stage 5c: enriched %d/%d clusters, lookup_size=%d', _ei_ok, len(clusters), len(_row_lookup_ei))
            _progress('reasoning', 73, f'Cluster intelligence enrichments complete ({_ei_ok} clusters)')
        except Exception as exc:
            logger.warning('cluster intelligence enrichment stage failed for %s: %s', assessment_id, exc, exc_info=True)

        # ── Stage 5x: aggregate hunt-lane factor tags into each cluster ───────
        # Runs _collect_lane_factor_tags() (synchronous pattern scan) over
        # filtered_rows then folds the per-row factors into cluster.factor_tags
        # so the breach.html factor panel, tier-2 dispatch, and SBOM surfaces
        # all see inbox_rule / fusion / storyline signals without requiring the
        # full async live-event lane infrastructure.
        try:
            try:
                _factor_scan_rows = await asyncio.to_thread(_store.load_all_rows, assessment_id)
            except Exception:
                _factor_scan_rows = filtered_rows
            _lane_factors_by_row = _collect_lane_factor_tags(_factor_scan_rows)
            _lane_factors_by_user: dict[str, set[str]] = {}
            _lane_factors_by_host: dict[str, set[str]] = {}
            _host_users_5x: dict[str, set[str]] = {}
            _global_high_signal_factors_5x: set[str] = set()
            _recon_counts_by_user_5x: dict[str, int] = {}
            _RECON_KEYWORDS_5X = (
                "net group", "net user", "dsquery", "setspn", "get-aduser",
                "get-adcomputer", "get-adgroup", "nltest", "invoke-sharphound",
                "sharphound", "get-domainuser", "get-domaincomputer", "get-domaingroupmember",
            )

            def _row_user_5x(row: dict) -> str:
                return str(
                    row.get("user_canonical") or row.get("user") or
                    row.get("account_name") or row.get("userPrincipalName") or
                    row.get("user_principal_name") or ""
                ).strip().lower()

            def _row_host_5x(row: dict) -> str:
                return str(
                    row.get("host") or row.get("hostname") or row.get("src_host") or
                    row.get("source_host") or row.get("workstation") or ""
                ).strip().lower()

            for _row_hu_5x in _factor_scan_rows:
                if not isinstance(_row_hu_5x, dict):
                    continue
                _u_hu_5x = _row_user_5x(_row_hu_5x)
                _h_hu_5x = _row_host_5x(_row_hu_5x)
                if _u_hu_5x and _h_hu_5x:
                    _host_users_5x.setdefault(_h_hu_5x, set()).add(_u_hu_5x)

            # Augment lane factors with IAM phase-3 kerberos / persistence detections
            try:
                from src.core.detectors.iam_phase3_4 import detect_identity_phase3 as _det_iam3
                _IAM_SRC_5X = {"windows_security", "identity_kerberos", "windows_event", "kerberos", "winevent", "iam"}
                _IAM_EIDS_5X = {"4768", "4769", "4770", "4771", "4624", "4625", "4720", "4728", "4732", "4756"}
                _iam3_hit_count = 0
                for _row_iam in _factor_scan_rows:
                    if not isinstance(_row_iam, dict):
                        continue
                    _src_iam = str(
                        _row_iam.get("source_type") or _row_iam.get("_source_type") or
                        _row_iam.get("log_source") or ""
                    ).lower()
                    _eid_iam = str(_row_iam.get("windows_event_id") or _row_iam.get("event_id") or "").strip()
                    if _src_iam not in _IAM_SRC_5X and _eid_iam not in _IAM_EIDS_5X:
                        continue
                    _ri_iam = _row_iam.get("row_index")
                    if _ri_iam is None:
                        continue
                    try:
                        _ri_key = int(float(_ri_iam))
                    except (TypeError, ValueError):
                        continue
                    _iam_factors, _ = _det_iam3(_row_iam)
                    if _iam_factors:
                        _existing_iam = _lane_factors_by_row.get(_ri_key) or []
                        _lane_factors_by_row[_ri_key] = list(set(_existing_iam) | set(_iam_factors))
                        _global_high_signal_factors_5x.update(
                            f for f in _iam_factors
                            if f in {"iam:as_rep_roasting", "iam:kerberoasting", "iam:golden_ticket"}
                        )
                        _iam3_hit_count += 1
                logger.info("Stage 5x: IAM phase-3 augmented %d rows for %s", _iam3_hit_count, assessment_id)
            except Exception as _iam_exc:
                logger.debug("IAM phase-3 augmentation in Stage 5x failed: %s", _iam_exc)

            # Augment cloud identity rows with OAuth consent / service-principal persistence factors.
            try:
                from src.core.detectors.iam_phase3_4 import detect_cloud_identity_phase4 as _det_cloud4
                _CLOUD_SRC_5X = {"cloud_identity", "azure_ad", "entra", "aad", "iam", "cloud"}
                _cloud4_hit_count = 0
                for _row_cloud in _factor_scan_rows:
                    if not isinstance(_row_cloud, dict):
                        continue
                    _src_cloud = str(
                        _row_cloud.get("source_type") or _row_cloud.get("_source_type") or
                        _row_cloud.get("log_source") or ""
                    ).lower()
                    _event_cloud = str(
                        _row_cloud.get("event_type") or _row_cloud.get("operation") or
                        _row_cloud.get("event_name") or _row_cloud.get("activityDisplayName") or ""
                    ).lower()
                    if _src_cloud not in _CLOUD_SRC_5X and not any(
                        k in _event_cloud for k in ("oauth", "consent", "addkey", "addpassword")
                    ):
                        continue
                    _ri_cloud = _row_cloud.get("row_index")
                    if _ri_cloud is None:
                        continue
                    try:
                        _ri_key = int(float(_ri_cloud))
                    except (TypeError, ValueError):
                        continue
                    _cloud_factors, _ = _det_cloud4(_row_cloud)
                    if _cloud_factors:
                        _existing_cloud = _lane_factors_by_row.get(_ri_key) or []
                        _lane_factors_by_row[_ri_key] = list(set(_existing_cloud) | set(_cloud_factors))
                        _cloud4_hit_count += 1
                logger.info("Stage 5x: cloud IAM phase-4 augmented %d rows for %s", _cloud4_hit_count, assessment_id)
            except Exception as _cloud_exc:
                logger.debug("Cloud IAM phase-4 augmentation in Stage 5x failed: %s", _cloud_exc)

            for _row_fx in _factor_scan_rows:
                if not isinstance(_row_fx, dict):
                    continue
                _ri_fx = _row_fx.get("row_index")
                if _ri_fx is None:
                    continue
                try:
                    _row_factors_fx = set(_lane_factors_by_row.get(int(float(_ri_fx))) or [])
                except (TypeError, ValueError):
                    _row_factors_fx = set()
                _u_fx = _row_user_5x(_row_fx)
                _h_fx = _row_host_5x(_row_fx)
                if not _u_fx and _h_fx:
                    _mapped_users_fx = _host_users_5x.get(_h_fx) or set()
                    if len(_mapped_users_fx) == 1:
                        _u_fx = next(iter(_mapped_users_fx))
                if _u_fx:
                    _cmd_fx = str(_row_fx.get("command_line") or _row_fx.get("cmdline") or "").lower()
                    if any(_kw_fx in _cmd_fx for _kw_fx in _RECON_KEYWORDS_5X):
                        _recon_counts_by_user_5x[_u_fx] = _recon_counts_by_user_5x.get(_u_fx, 0) + 1
                    if _row_factors_fx:
                        _lane_factors_by_user.setdefault(_u_fx, set()).update(_row_factors_fx)
                if _h_fx:
                    if _row_factors_fx:
                        _lane_factors_by_host.setdefault(_h_fx, set()).update(_row_factors_fx)

            _RECON_SEQ_MIN_5X = int(os.getenv("JANUSEC_RECON_SEQUENCE_EVENT_MIN", "4"))
            for _u_recon_5x, _cnt_recon_5x in _recon_counts_by_user_5x.items():
                if _cnt_recon_5x >= _RECON_SEQ_MIN_5X:
                    _lane_factors_by_user.setdefault(_u_recon_5x, set()).add("recon:sustained_offhours_sequence")

            def _cluster_principals_5x(cluster: dict) -> set[str]:
                _vals: set[str] = set()
                for _key in ("shared_users", "shared_accounts"):
                    for _v in cluster.get(_key) or []:
                        if _v:
                            _vals.add(str(_v).strip().lower())
                _ap = cluster.get("affected_principals") or {}
                if isinstance(_ap, dict):
                    for _key in ("users", "accounts", "service_accounts"):
                        for _v in _ap.get(_key) or []:
                            if _v:
                                _vals.add(str(_v).strip().lower())
                elif isinstance(_ap, (list, tuple, set)):
                    for _v in _ap:
                        if _v:
                            _vals.add(str(_v).strip().lower())
                return _vals

            def _cluster_hosts_5x(cluster: dict) -> set[str]:
                _vals: set[str] = set()
                for _key in ("shared_hosts", "hosts"):
                    for _v in cluster.get(_key) or []:
                        if _v:
                            _vals.add(str(_v).strip().lower())
                _ap = cluster.get("affected_principals") or {}
                if isinstance(_ap, dict):
                    for _v in _ap.get("hosts") or []:
                        if _v:
                            _vals.add(str(_v).strip().lower())
                return _vals

            _fx_count = 0
            for _cl in clusters:
                _cl_factor_set: set[str] = set(_cl.get("factor_tags") or [])
                _campaign_factor_set: set[str] = set(_cl.get("_campaign_factor_tags") or [])
                for _ref in (_cl.get("row_refs") or []):
                    try:
                        _rk = int(float(_ref))
                        _row_factors = _lane_factors_by_row.get(_rk)
                        if _row_factors:
                            _cl_factor_set.update(_row_factors)
                    except (TypeError, ValueError):
                        pass
                for _u_fx in _cluster_principals_5x(_cl):
                    _campaign_factor_set.update(_lane_factors_by_user.get(_u_fx) or set())
                for _h_fx in _cluster_hosts_5x(_cl):
                    _campaign_factor_set.update(_lane_factors_by_host.get(_h_fx) or set())
                _srcs_fx = {
                    str(s).strip().lower()
                    for s in ((_cl.get("sources") or []) + (_cl.get("source_types") or []))
                    if s
                }
                if _global_high_signal_factors_5x and (
                    "iam" in _srcs_fx
                    or "identity_kerberos" in _srcs_fx
                ):
                    _cl_factor_set.update(_global_high_signal_factors_5x)
                elif _global_high_signal_factors_5x:
                    _campaign_factor_set.update(_global_high_signal_factors_5x)
                if _cl_factor_set:
                    _cl["factor_tags"] = sorted(_cl_factor_set)
                    _fx_count += 1
                if _campaign_factor_set:
                    _cl["_campaign_factor_tags"] = sorted(_campaign_factor_set - _cl_factor_set)
            logger.info("Stage 5x: factor tags aggregated into %d clusters for %s", _fx_count, assessment_id)

            # ── Severity retrofix ───────────────────────────────────────────────
            # Stage 1 (_score_async_ingest_row) runs BEFORE factor_tags exist, so
            # Kerberos / LOLbin / IAM rows always score medium.  Now that
            # _lane_factors_by_row is populated, push severity back to both
            # _factor_scan_rows and filtered_rows so the API returns the right value.
            _retro_pairs: list[tuple[int, str]] = []
            for _rk_rt, _rft_rt in _lane_factors_by_row.items():
                _fts_rt = set(_rft_rt)
                if _fts_rt & _CRITICAL_SEVERITY_FACTORS:
                    _retro_pairs.append((_rk_rt, 'critical'))
                elif _fts_rt & _HIGH_SEVERITY_FACTORS:
                    _retro_pairs.append((_rk_rt, 'high'))
            if _retro_pairs:
                _retro_map: dict[int, str] = dict(_retro_pairs)
                for _r_rt in (*_factor_scan_rows, *filtered_rows):
                    _ri_rt = _r_rt.get('row_index')
                    if _ri_rt is None:
                        continue
                    try:
                        _rk_rt2 = int(float(_ri_rt))
                    except (TypeError, ValueError):
                        continue
                    _new_sev_rt = _retro_map.get(_rk_rt2)
                    if not _new_sev_rt:
                        continue
                    if str(_r_rt.get('_severity') or '').lower() in ('critical', 'high'):
                        continue
                    _r_rt['_severity'] = _new_sev_rt
                    if not _r_rt.get('factor_tags'):
                        _r_rt['factor_tags'] = sorted(_lane_factors_by_row.get(_rk_rt2) or [])
                logger.info("Stage 5x: severity retrofix elevated %d rows for %s",
                            len(_retro_pairs), assessment_id)
        except Exception as exc:
            logger.debug("Lane factor tag aggregation failed for %s: %s", assessment_id, exc)

        # ── Stage 5y: populate per-cluster evidence_preview ───────────────────
        # Clusters only store row_ref indices; the breach.html cluster card
        # needs a sample of actual row dicts to render the in-cluster evidence
        # table without a second API round-trip.  Populate evidence_preview
        # (up to 20 rows, ranked by triage_score desc, source-balanced).
        # IMPORTANT: We sort by triage_score before slicing, not by row order —
        # ingestion order biases toward whichever file is processed first, which
        # causes high-signal attack rows (Kerberos EventID 4769, LOLBins cmd lines)
        # from later files to be excluded in favour of low-score cloud rows.
        try:
            _row_lookup_ep: dict[int, dict] = {}
            for _r in filtered_rows:
                _ri = _r.get("row_index")
                if _ri is not None:
                    try:
                        _row_lookup_ep[int(float(_ri))] = _r
                    except (TypeError, ValueError):
                        pass
            _ep_count = 0
            _EP_CAP = 20
            for _cl in clusters:
                if _cl.get("evidence_preview"):
                    continue  # already populated upstream
                # Collect all matching rows first, then rank
                _candidate_rows: list[dict] = []
                for _ref in (_cl.get("row_refs") or []):
                    try:
                        _r = _row_lookup_ep.get(int(float(_ref)))
                        if _r:
                            _candidate_rows.append(_r)
                    except (TypeError, ValueError):
                        pass
                # Sort by triage_score desc so high-signal attack rows surface first
                _candidate_rows.sort(
                    key=lambda r: float(r.get("triage_score") or 0), reverse=True
                )
                # Source-balance: ensure at most ceil(EP_CAP/unique_sources) per source,
                # then fill remaining slots from the ranked list.
                _seen_sources: dict[str, int] = {}
                _preview: list[dict] = []
                _source_cap = max(4, _EP_CAP // max(1, len({
                    r.get("_source") or r.get("source_file", "") for r in _candidate_rows
                })))
                for _r in _candidate_rows:
                    _src = str(_r.get("_source") or _r.get("source_file") or "")
                    if _seen_sources.get(_src, 0) >= _source_cap and len(_preview) < _EP_CAP:
                        continue  # skip over-represented source; fill from others first
                    _seen_sources[_src] = _seen_sources.get(_src, 0) + 1
                    _preview.append(_r)
                    if len(_preview) >= _EP_CAP:
                        break
                # If source balancing left slots, fill with any remaining rows
                if len(_preview) < _EP_CAP:
                    _added = set(id(r) for r in _preview)
                    for _r in _candidate_rows:
                        if id(_r) not in _added:
                            _preview.append(_r)
                            if len(_preview) >= _EP_CAP:
                                break
                if _preview:
                    _cl["evidence_preview"] = _preview
                    _ep_count += 1
            logger.info("Stage 5y: evidence_preview populated for %d clusters (%d rows lookup) for %s",
                        _ep_count, len(_row_lookup_ep), assessment_id)
        except Exception as exc:
            logger.debug("evidence_preview population failed for %s: %s", assessment_id, exc)

        # ── Stage 5g: feed IdentityGraph + MLSignalAggregator ───────────────
        # Populates GLOBAL_IDENTITY_GRAPH so retrieve_identity_context() in persona
        # dispatch has real lateral-movement paths for this assessment's actors.
        # Simultaneously accumulates per-event iso_score/ensemble_score/EWMA residuals
        # in ASSESSMENT_ML_SIGNALS for Stage 5g+ read-back below.
        try:
            from src.core.graph.identity_hopgraph import GLOBAL_IDENTITY_GRAPH as _ig
            from src.ml.signal_aggregator import ASSESSMENT_ML_SIGNALS as _ml_agg
            _ml_agg.clear()
            _ig_count = 0
            _ig_cap = int(os.getenv("JANUSEC_IDENTITY_GRAPH_CAP", "10000"))
            for _row_ig in filtered_rows[:_ig_cap]:
                if not isinstance(_row_ig, dict):
                    continue
                try:
                    _ig.ingest_identity_event(_row_ig, aggregator=_ml_agg)
                    _ig_count += 1
                except Exception:
                    continue
            logger.info(
                "Stage 5g: ingested %d rows into IdentityGraph for %s "
                "(%d users tracked by ML aggregator)",
                _ig_count, assessment_id, len(_ml_agg),
            )
            # Flush to SQLite so TemporalRAG.retrieve_identity_context() can read
            # the lateral-movement paths built above during persona dispatch.
            try:
                from src.core.graph.global_identity_graph import flush_global_identity_graph
                flush_global_identity_graph()
                logger.info("Stage 5g: identity graph flushed for %s", assessment_id)
            except Exception as _flush_exc:
                logger.debug("Stage 5g: identity graph flush failed for %s: %s",
                             assessment_id, _flush_exc)
        except Exception as exc:
            logger.debug("IdentityGraph ingestion skipped for %s: %s", assessment_id, exc)

        # ── Stage 5h: update BaselineService (MOVED before persona dispatch) ──
        try:
            from src.core.baseline_service import BASELINES as _bl
            import asyncio as _asyncio
            _bl_user_counts: dict[str, int] = {}
            _bl_host_counts: dict[str, int] = {}
            _bl_user_bytes: dict[str, float] = {}
            _host_users_bl: dict[str, set[str]] = {}
            for _row_bl in filtered_rows:
                if not isinstance(_row_bl, dict):
                    continue
                _u = str(_row_bl.get("user_canonical") or _row_bl.get("user") or "").strip().lower()
                _h = str(
                    _row_bl.get("host") or _row_bl.get("hostname") or
                    _row_bl.get("src_host") or _row_bl.get("source_host") or ""
                ).strip().lower()
                if _u and _h:
                    _host_users_bl.setdefault(_h, set()).add(_u)
            for _row_bl in filtered_rows:
                if not isinstance(_row_bl, dict):
                    continue
                _u = str(_row_bl.get("user_canonical") or _row_bl.get("user") or "").strip().lower()
                _h = str(
                    _row_bl.get("host") or _row_bl.get("hostname") or
                    _row_bl.get("src_host") or _row_bl.get("source_host") or ""
                ).strip().lower()
                if not _u and _h:
                    _mapped_users = _host_users_bl.get(_h) or set()
                    if len(_mapped_users) == 1:
                        _u = next(iter(_mapped_users))
                if _u:
                    _bl_user_counts[_u] = _bl_user_counts.get(_u, 0) + 1
                    _bytes = float(_row_bl.get("bytes_out") or _row_bl.get("bytes_sent") or _row_bl.get("orig_bytes") or _row_bl.get("bytes") or 0)
                    if _bytes > 0:
                        _bl_user_bytes[_u] = _bl_user_bytes.get(_u, 0.0) + _bytes
                if _h:
                    _bl_host_counts[_h] = _bl_host_counts.get(_h, 0) + 1
            _bl_loop = _asyncio.get_event_loop()
            for _u, _cnt in _bl_user_counts.items():
                _bl_loop.create_task(_bl.update("user", _u, "events_per_assessment", float(_cnt)))
            for _u, _byt in _bl_user_bytes.items():
                _bl_loop.create_task(_bl.update("user", _u, "bytes_per_assessment", _byt))
            for _h, _cnt in _bl_host_counts.items():
                _bl_loop.create_task(_bl.update("host", _h, "events_per_assessment", float(_cnt)))
            logger.info(
                "Stage 5h: queued baseline updates for %d users / %d hosts (assessment %s)",
                len(_bl_user_counts), len(_bl_host_counts), assessment_id,
            )
        except Exception as exc:
            logger.debug("BaselineService update skipped for %s: %s", assessment_id, exc)

        # ── Stage 5i: ChronoGraph accumulation (extracted → chrono.pipeline) ──
        # Runs the SAME long-horizon detection the ground-truth gate runs (one source of
        # truth; entity_metrics is now data-time anchored, fixing historical assessments).
        from src.core.chrono.pipeline import accumulate as _chrono_accumulate, elevate_clusters as _chrono_elevate
        _chrono_accum = None
        _chrono_ref_ts = 0.0
        try:
            from src.core.chrono.sketch_store import CHRONO as _chrono
            try:
                _chrono_rows = await asyncio.to_thread(
                    _store.load_rows, assessment_id, min_triage=0.0, limit=CHRONO_ROW_CAP,
                )
            except Exception:
                _chrono_rows = None
            if not _chrono_rows:
                _chrono_rows = filtered_rows
            # Entity resolution on the full-telemetry set too, so host-only exfil rows
            # carry the actor and their cumulative per-destination bytes accumulate under
            # the right user (the signal that stitches exfil to the campaign).
            from src.core.entity_resolver import resolve_entities as _resolve_entities
            _resolve_entities(_chrono_rows)
            logger.info("Stage 5i: ChronoGraph over %d rows (vs %d clustered) for %s",
                        len(_chrono_rows), len(filtered_rows), assessment_id)
            _chrono_accum = _chrono_accumulate(_chrono_rows, _chrono)
            _chrono_ref_ts = _chrono_accum.ref_ts
            logger.info("Stage 5i: ChronoGraph accumulated %d rows for %s", len(_chrono_rows), assessment_id)
        except Exception as exc:
            logger.debug("ChronoGraph accumulation skipped for %s: %s", assessment_id, exc)

        # ── Stage 5j: ChronoGraph anomaly → cluster factor elevation (extracted) ──
        try:
            from src.core.chrono.sketch_store import CHRONO as _chrono_j
            if _chrono_accum is not None:
                _chrono_elevate(clusters, _chrono_accum, _chrono_j)
            logger.info("Stage 5j: ChronoGraph anomaly elevation done for %s", assessment_id)
        except Exception as exc:
            logger.debug("Stage 5j ChronoGraph elevation skipped for %s: %s", assessment_id, exc)

        # ── Stage 5g+: ML signal read-back + cross-source ISO scoring ────────
        # After Stage 5g populated IdentityGraph and 5i populated ChronoGraph,
        # read identity_snapshot() risk/EWMA per cluster principal, build a
        # cross-source feature vector (combining ChronoGraph z-scores with
        # aggregated ISO/EWMA residuals), score it, and elevate cluster
        # factor_tags + apply a capped triage_score boost.
        try:
            from src.core.graph.identity_hopgraph import GLOBAL_IDENTITY_GRAPH as _ig_gp
            from src.core.chrono.sketch_store import CHRONO as _chrono_gp
            from src.ml.signal_aggregator import ASSESSMENT_ML_SIGNALS as _ml_agg_gp
            from src.ml.isolation_model import GLOBAL_ISO_MODEL as _iso_gp

            # Write aggregated ML counts into ChronoGraph for cross-assessment tracking
            import time as _time_gp
            _ml_agg_gp.to_chrono_metrics(_chrono_gp, ts=_time_gp.time())

            def _safe_z(chrono, etype, entity, metric, window=86400 * 7):
                try:
                    return float(chrono.z_score(etype, entity, metric,
                                               window_seconds=window,
                                               reference_ts=(_chrono_ref_ts or None)).get("z") or 0.0)
                except Exception:
                    return 0.0

            def _build_user_feature_vector(user, chrono, agg_summary):
                """8-dimensional cross-source feature vector per user."""
                return [
                    _safe_z(chrono, "user", user, "off_hours_recon_events"),
                    _safe_z(chrono, "user", user, "bytes_out"),
                    _safe_z(chrono, "user", user, "cloud_bytes_out"),
                    _safe_z(chrono, "user", user, "iam:rc4_count"),
                    _safe_z(chrono, "user", user, "cloud:foreign_asn_count"),
                    _safe_z(chrono, "user", user, "endpoint:lolbin_count"),
                    float(agg_summary.get("peak_iso") or 0.0),
                    float(agg_summary.get("peak_ewma_residual") or 0.0),
                ]

            # Bootstrap ISO model from this assessment's user feature vectors before scoring
            _iso_boot_vecs: list[list[float]] = []
            for _u_boot in _ml_agg_gp.all_users():
                try:
                    _boot_sum = _ml_agg_gp.summary(_u_boot)
                    _boot_vec = _build_user_feature_vector(_u_boot, _chrono_gp, _boot_sum)
                    _iso_boot_vecs.append(_boot_vec)
                except Exception:
                    continue
            if len(_iso_boot_vecs) >= 5:
                try:
                    _iso_gp.fit_partial(_iso_boot_vecs)
                    logger.info("Stage 5g+: ISO bootstrap trained on %d user vectors for %s", len(_iso_boot_vecs), assessment_id)
                except Exception as _iso_boot_exc:
                    logger.debug("Stage 5g+ ISO bootstrap failed for %s: %s", assessment_id, _iso_boot_exc)

            _BREACH_VERD_GP = {"VALIDATED_BREACH", "LIKELY_BREACH", "LIKELY_COMPROMISE", "INCIDENT"}
            for _cl_gp in clusters:
                _verd_gp = str(_cl_gp.get("final_verdict") or _cl_gp.get("verdict") or "").upper()
                if _verd_gp not in _BREACH_VERD_GP:
                    continue
                _princ_gp = [
                    str(u).strip().lower() for u in (
                        _cl_gp.get("affected_principals") or _cl_gp.get("shared_accounts") or
                        _cl_gp.get("shared_users") or []
                    ) if u
                ][:4]
                _ml_tags: list[str] = []
                _triage_boost = 0.0

                for _u_gp in _princ_gp:
                    # Identity risk from IdentityGraph state machine + EWMA
                    _snap = _ig_gp.identity_snapshot(f"user:{_u_gp}")
                    _risk = float(_snap.get("risk") or 0.0)
                    _ewma_d = _snap.get("ewma") or {}
                    _ewma_res = abs(float(_ewma_d.get("residual_last") or 0.0))

                    if _risk > 0.70:
                        _ml_tags.append("identity:ml_risk_spike")
                        _triage_boost = max(_triage_boost, min(0.08, (_risk - 0.5) * 0.1))
                    if _ewma_res > 1.5:
                        _ml_tags.append("identity:ewma_behavioral_spike")
                        _triage_boost = max(_triage_boost, 0.04)

                    # Cross-source isolation forest score
                    _agg_sum = _ml_agg_gp.summary(_u_gp)
                    _feats = _build_user_feature_vector(_u_gp, _chrono_gp, _agg_sum)
                    try:
                        _cross_iso = float(_iso_gp.score(_feats))
                    except Exception:
                        _cross_iso = 0.0
                    if _cross_iso > 0.65:
                        _ml_tags.append("identity:iso_cross_source_anomaly")
                        _triage_boost = max(_triage_boost, min(0.10, _cross_iso * 0.12))

                    # Persist cross-source scores onto cluster for LLM context
                    _cl_gp.setdefault("_ml_scores", {})[_u_gp] = {
                        "risk": round(_risk, 3),
                        "ewma_residual": round(_ewma_res, 3),
                        "cross_iso": round(_cross_iso, 3),
                        "peak_iso": round(float(_agg_sum.get("peak_iso") or 0), 3),
                        "anomaly_rate": round(float(_agg_sum.get("anomaly_rate") or 0), 3),
                    }

                    # Index into TemporalRAG so future assessments can retrieve
                    # prior ML anomalies for this user (fifth RAG silo)
                    if _ml_tags or _cross_iso > 0.50 or _risk > 0.50:
                        try:
                            from src.analysis.temporal_rag_dispatch import TemporalRAGProvider as _TRP_gp
                            _rag_idx = _TRP_gp(
                                incident_store=_get_incident_index(),
                                decision_store=_get_trace_store(),
                                tenant_id=org,
                            )
                            _z_snap = {
                                "off_hours_recon_events": _safe_z(_chrono_gp, "user", _u_gp, "off_hours_recon_events"),
                                "bytes_out": _safe_z(_chrono_gp, "user", _u_gp, "bytes_out"),
                                "iam:rc4_count": _safe_z(_chrono_gp, "user", _u_gp, "iam:rc4_count"),
                            }
                            _rag_idx.index_ml_anomaly(
                                user=_u_gp,
                                iso_score=max(_cross_iso, float(_agg_sum.get("peak_iso") or 0)),
                                z_scores=_z_snap,
                                factor_tags=_ml_tags or list(_cl_gp.get("factor_tags") or [])[:6],
                                assessment_id=assessment_id,
                                ts=_time_gp.time(),
                            )
                        except Exception:
                            pass

                # Apply tags and triage boost
                if _ml_tags:
                    _existing_gp = _cl_gp.setdefault("factor_tags", [])
                    for _t in set(_ml_tags):
                        if _t not in _existing_gp:
                            _existing_gp.append(_t)
                if _triage_boost > 0:
                    _cl_gp["triage_score"] = min(
                        1.0, float(_cl_gp.get("triage_score") or 0.5) + _triage_boost
                    )
            logger.info("Stage 5g+: ML signal read-back and cross-source ISO done for %s", assessment_id)
        except Exception as exc:
            logger.debug("Stage 5g+ ML read-back skipped for %s: %s", assessment_id, exc)

        # ── Stage 5k: compliance control violation mapping ────────────────────
        # Maps cluster factor_tags to NIST 800-53, ISO 27001, CIS v8, SOC 2.
        # Sets cluster["compliance_violations"] consumed by breach.js, exec summary,
        # and compliance persona LLM prompt.
        try:
            from src.explain.compliance_mapper import map_factors_to_controls as _map_controls
            for _cl_k in clusters:
                _ftags_k = _cl_k.get("factor_tags") or []
                if _ftags_k:
                    _cl_k["compliance_violations"] = _map_controls(_ftags_k)
            logger.info("Stage 5k: compliance mapping done for %s", assessment_id)
        except Exception as exc:
            logger.debug("Stage 5k compliance mapping skipped for %s: %s", assessment_id, exc)

        # ── Stage 5l: cross-engine Pattern Synthesis ──────────────────────────
        # Depends on Stage 5g (IdentityGraph), 5i (ChronoGraph accumulation),
        # 5j (z-score elevation), and 5g+ (ML signals) completing first.
        # Produces a unified per-principal anomaly multiplier that boosts cluster
        # confidence when BOTH temporal anomaly AND graph risk are elevated.
        try:
            from src.core.synthesis.pattern_synthesizer import synthesize_cluster_signals
            from src.core.chrono.sketch_store import CHRONO as _CHRONO_5l
            from src.core.graph.identity_hopgraph import GLOBAL_IDENTITY_GRAPH as _IG_5l
            # ASSESSMENT_ML_SIGNALS is populated by Stage 5g — each event's iso/ensemble
            # scores are recorded there.  We query per principal below.
            from src.ml.signal_aggregator import ASSESSMENT_ML_SIGNALS as _ML_5l
            _synth_boosted = 0
            for _cl_5l in clusters:
                if not _is_breach_cluster(_cl_5l):
                    continue
                try:
                    # Build a per-cluster ml_signals dict: best peak across all principals
                    _princ_5l = list(dict.fromkeys(
                        (_cl_5l.get('shared_accounts') or []) +
                        (_cl_5l.get('shared_users') or [])
                    ))[:5]
                    _best_ml: dict = {}
                    for _p5l in _princ_5l:
                        _s5l = _ML_5l.summary(str(_p5l).strip().lower())
                        if float(_s5l.get('peak_iso') or 0) > float(_best_ml.get('peak_iso') or 0):
                            _best_ml = _s5l
                    _syn = synthesize_cluster_signals(_cl_5l, _CHRONO_5l, _IG_5l, _best_ml)
                    _cl_5l['_synthesis'] = _syn
                    if _syn.get('triggered'):
                        _cl_5l['confidence'] = min(
                            1.0,
                            float(_cl_5l.get('confidence') or 0.0) + _syn['confidence_boost'],
                        )
                        _ftags_5l = list(_cl_5l.get('factor_tags') or [])
                        if 'identity:cross_engine_anomaly' not in _ftags_5l:
                            _ftags_5l.append('identity:cross_engine_anomaly')
                            _cl_5l['factor_tags'] = _ftags_5l
                        _synth_boosted += 1
                except Exception as _syn_err:
                    logger.debug('Pattern Synthesizer failed for cluster %s: %s',
                                 _cl_5l.get('cluster_id'), _syn_err)
            logger.info(
                'Stage 5l: Pattern Synthesis done for %s — %d clusters boosted',
                assessment_id, _synth_boosted,
            )
        except Exception as exc:
            logger.debug('Stage 5l Pattern Synthesis skipped for %s: %s', assessment_id, exc)

        # ── Stage 5d: persona dispatch + framework mapping + bitemporal trace ──
        # Enriches each breach cluster's narrative with structured data (affected
        # principals, data sensitivity, attacker infra), builds the control
        # failure register, generates per-persona dispatch payloads, and wraps
        # each in a bitemporal decision trace for audit replay.
        # NOTE: Runs AFTER 5g/5h/5i/5j so IdentityGraph and ChronoGraph are populated.
        if clusters:
            _progress("reasoning", 76, "Generating grounded LLM narratives for top clusters")
            # narrate_top_clusters self-budgets via the SAME env var (default 600s) and
            # degrades gracefully per-cluster. This outer asyncio.wait_for is only a safety
            # net against a total hang, so it MUST exceed the inner budget — otherwise it
            # cancels narration mid-stage (a single 14b cluster takes ~30s + ~40s critic,
            # so the old hard-coded 50s axed multi-cluster runs after 1-2 clusters).
            _narrate_inner_budget = float(os.getenv("JANUSEC_INGEST_NARRATE_TIMEOUT_S", "600"))
            _narrate_timeout = _narrate_inner_budget + 60.0
            try:
                from src.core.ingest.cluster_narrator import narrate_top_clusters
                await asyncio.wait_for(
                    asyncio.to_thread(
                        narrate_top_clusters,
                        clusters,
                        filtered_rows,
                        assessment_id=assessment_id,
                    ),
                    timeout=_narrate_timeout,
                )
            except asyncio.TimeoutError:
                logger.warning(
                    "cluster narration timed out (>%.0fs) for %s - using fallback narratives",
                    _narrate_timeout, assessment_id,
                )
            except Exception as exc:
                logger.warning("cluster narration failed for %s: %s", assessment_id, exc)

            # Post-hoc confidence calibration: when LLM is unavailable the fallback
            # hard-codes 0.3. Evidence-weight floor prevents a 49-row VALIDATED_BREACH
            # cluster from showing the same confidence as a 2-row REQUIRES_INVESTIGATION.
            for _cl_cal in clusters:
                _calibrate_cluster_confidence(_cl_cal)

        # ── Stage 5c+: operator sanctioned-context (suppress authorized pentest,
        # elevate crown-jewel touches). No-op when no context file is configured. ──
        try:
            from src.core.operator_context import load_operator_context
            _opctx = load_operator_context()
            if not _opctx.is_empty:
                _suppressed = _elevated = 0
                for _cl_oc in clusters:
                    if _opctx.cluster_is_authorized_pentest(_cl_oc):
                        _cl_oc["_authorized_pentest"] = True
                        _cl_oc["final_verdict"] = "BENIGN_EXPECTED"
                        _cl_oc["verdict"] = "BENIGN_EXPECTED"
                        _cl_oc.setdefault("factor_tags", [])
                        if "ops:authorized_pentest" not in _cl_oc["factor_tags"]:
                            _cl_oc["factor_tags"].append("ops:authorized_pentest")
                        _suppressed += 1
                        continue  # authorized — do not also elevate
                    _cj = _opctx.touches_crown_jewel(_cl_oc)
                    if _cj:
                        _cl_oc["_crown_jewels_touched"] = _cj
                        _cl_oc.setdefault("factor_tags", [])
                        if "impact:crown_jewel_access" not in _cl_oc["factor_tags"]:
                            _cl_oc["factor_tags"].append("impact:crown_jewel_access")
                        _cl_oc["severity"] = "critical"
                        _elevated += 1
                if _suppressed or _elevated:
                    logger.info("operator context: %d pentest cluster(s) suppressed, "
                                "%d crown-jewel cluster(s) elevated for %s",
                                _suppressed, _elevated, assessment_id)
        except Exception as exc:
            logger.debug("operator context stage skipped for %s: %s", assessment_id, exc)

        _progress("reasoning", 78, "Building persona dispatch payloads")
        try:
            _enrich_and_dispatch_personas(assessment, clusters, filtered_rows, org)
        except Exception as exc:
            logger.warning("persona dispatch stage failed for %s: %s", assessment_id, exc, exc_info=True)

        # ── Stage 5e: index evidence rows into TemporalRAG ───────────────────
        try:
            _rag_cap = int(os.getenv("JANUSEC_TEMPORAL_RAG_INDEX_CAP", "25"))
            _rag_async = os.getenv("JANUSEC_TEMPORAL_RAG_INDEX_ASYNC", "1").strip().lower() not in {"0", "false", "no"}
            _rag_rows = [dict(r) for r in (filtered_rows[:_rag_cap] if _rag_cap > 0 else []) if isinstance(r, dict)]

            def _index_temporal_rag_rows(rows_snapshot: list[dict]) -> int:
                from src.ai.temporal_rag import get_engine as _get_rag_engine
                _rag = _get_rag_engine()
                return _rag.index_rows(rows_snapshot, tenant=org, assessment_id=assessment_id) if _rag and rows_snapshot else 0

            if _rag_rows and _rag_async:
                async def _run_temporal_rag_index() -> None:
                    try:
                        _rag_count = await asyncio.to_thread(_index_temporal_rag_rows, _rag_rows)
                        logger.info(
                            "Stage 5e: background indexed %d/%d rows into TemporalRAG for %s (cap=%d)",
                            _rag_count, len(filtered_rows), assessment_id, _rag_cap,
                        )
                    except Exception as exc:
                        logger.debug("TemporalRAG background row indexing skipped for %s: %s", assessment_id, exc)

                asyncio.create_task(_run_temporal_rag_index())
                logger.info(
                    "Stage 5e: queued TemporalRAG background indexing for %s (%d/%d rows, cap=%d)",
                    assessment_id, len(_rag_rows), len(filtered_rows), _rag_cap,
                )
            elif _rag_rows:
                _rag_count = await asyncio.to_thread(_index_temporal_rag_rows, _rag_rows)
                logger.info(
                    "Stage 5e: indexed %d/%d rows into TemporalRAG for %s (cap=%d)",
                    _rag_count, len(filtered_rows), assessment_id, _rag_cap,
                )
            else:
                logger.info(
                    "Stage 5e: TemporalRAG row indexing disabled for %s (cap=%d)",
                    assessment_id, _rag_cap,
                )
        except Exception as exc:
            logger.debug("TemporalRAG row indexing skipped for %s: %s", assessment_id, exc)

        try:
            from src.graph.hopgraph import GLOBAL_HOPGRAPH as _hg
            _hg_count = 0
            if _hg is not None and hasattr(_hg, "ingest_event"):
                for _row_hg in filtered_rows[:5000]:
                    if not isinstance(_row_hg, dict):
                        continue
                    try:
                        _hg.ingest_event(_hopgraph_event_from_row(_row_hg), source=f"assessment:{assessment_id}")
                        _hg_count += 1
                    except Exception:
                        continue
                _node_count = len(getattr(_hg, "nodes", {}) or {})
                _edge_count = _hg.edge_count() if hasattr(_hg, "edge_count") else sum(
                    len(v) for v in (getattr(_hg, "adj", {}) or {}).values()
                )
                assessment["hopgraph_summary"] = {
                    "status": "populated" if _hg_count else "empty",
                    "ingested_rows": _hg_count,
                    "node_count": _node_count,
                    "edge_count": _edge_count,
                    "source": f"assessment:{assessment_id}",
                    "cap": 5000,
                }
                logger.info("Stage 5f: ingested %d rows into HopGraph for %s", _hg_count, assessment_id)
        except Exception as exc:
            logger.debug("HopGraph ingestion skipped for %s: %s", assessment_id, exc)

        # ── Stage 6: tier-1 prefill (top-10 cluster cards) ────────────────────
        _progress("reasoning", 85, "Tier-1 prefill for cluster cards")
        try:
            from src.api.deep_analyze_endpoints import _schedule_prefill_generation
            _schedule_prefill_generation(assessment, assessment_id)
        except Exception as exc:
            logger.debug("tier1 prefill scheduling skipped for %s: %s", assessment_id, exc)

        # ── Stage 6b: seed proposed_actions + kill_chain for breach clusters ───
        # Deterministic — gives the CEO banner + path-of-intrusion table content
        # without requiring the full agent investigation loop.
        # Also bridges threat_cases into the seeding input so that clusters
        # whose final_verdict is sub-threshold but whose corresponding threat_case
        # is VALIDATED_BREACH still produce proposed actions.
        try:
            _seed_clusters = list(clusters)
            _threat_cases = assessment.get("threat_cases") or []
            for _tc in _threat_cases:
                _tc_verdict = str(_tc.get("final_verdict") or _tc.get("verdict") or "").upper()
                if _tc_verdict in _BREACH_VERDICTS:
                    _proxy = dict(_tc)
                    _proxy.setdefault("final_verdict", _tc_verdict)
                    _proxy.setdefault("row_refs", _tc.get("row_refs") or [])
                    if not any(c.get("cluster_id") == _tc.get("cluster_id") or
                               c.get("case_id") == _tc.get("case_id") for c in _seed_clusters):
                        _seed_clusters.append(_proxy)
            _seed_proposed_actions_and_kill_chain(assessment, _seed_clusters, filtered_rows)
            logger.info("Stage 6b: seeded proposed_actions=%d, kill_chain=%d for %s",
                        len(assessment.get('proposed_actions', [])),
                        len(assessment.get('kill_chain', [])),
                        assessment_id)
        except Exception as exc:
            logger.debug("proposed_actions/kill_chain seeding skipped for %s: %s", assessment_id, exc)

        try:
            exec_result = _generate_deterministic_executive_summary(assessment, clusters, filtered_rows)
            assessment["executive_summary"] = exec_result.get("executive_summary", "")
            assessment["exec_summary_llm"] = exec_result
            # Promote compliance violations to top-level so the breach.html
            # frontend, /api/v1/assessments/{id} consumers, and downstream
            # report exporters can render an evidence-backed compliance panel.
            _cv = exec_result.get("compliance_violations") or []
            if _cv:
                assessment["compliance_violations"] = _cv
                logger.info(
                    "Stage 6c: surfaced %d compliance control violation(s) at top level for %s",
                    len(_cv), assessment_id,
                )
            logger.info("Stage 6c: deterministic executive summary generated for %s", assessment_id)
        except Exception as exc:
            logger.debug("Executive summary generation skipped for %s: %s", assessment_id, exc)

        # ── Stage 7: persist final assessment JSON ─────────────────────────────
        _progress("persisting", 92, "Saving assessment")
        assessment["evidence_rows"] = evidence_preview
        assessment.pop("rows", None)
        assessment.pop("all_rows", None)
        _persist_assessment_json(assessment_id, org, assessment)

        # Persist cluster snapshots to DuckDB
        try:
            await asyncio.to_thread(_store.persist_clusters, assessment_id, clusters)
        except Exception:
            pass

        _store.update_job(
            assessment_id,
            status="ready",
            stage="ready",
            percent=100,
            stage_label="Assessment ready",
        )
        logger.info("assessment %s complete — %d rows, %d clusters", assessment_id, total_rows, len(clusters))

    except Exception as exc:
        logger.exception("assessment pipeline failed for %s", assessment_id)
        try:
            from src.core.ingest import store as _store
            _store.update_job(assessment_id, status="failed", error=str(exc)[:500])
        except Exception:
            pass

    return assessment_id


# ── Deterministic proposed_actions + kill_chain seeding ────────────────────────

# Action templates keyed by MITRE tactic or evidence pattern.
# Each template produces a Zone 2 (auto-approvable) or Zone 3 (human-only) action.
_ACTION_TEMPLATES: list[dict] = [
    {
        "match": lambda c, rows: any(
            "credential" in (r.get("description") or "").lower()
            or "password" in (r.get("description") or "").lower()
            or "brute" in (r.get("description") or "").lower()
            for r in rows
        ),
        "zone": 2,
        "action_type": "credential_reset",
        "description": "Force credential rotation for compromised accounts",
        "recipient": "Identity Team",
        "deadline_hours": 4,
        "citation": "NIST SP 800-63B §5.1.1",
    },
    {
        "match": lambda c, rows: any(
            "exfil" in (r.get("description") or "").lower()
            or "backblaze" in (r.get("description") or "").lower()
            or "rclone" in (r.get("description") or "").lower()
            or "copy into" in (r.get("description") or "").lower()
            for r in rows
        ),
        "zone": 2,
        "action_type": "block_egress",
        "description": "Block outbound data transfer to unapproved cloud destinations",
        "recipient": "SOC",
        "deadline_hours": 1,
        "citation": "ISO 27001:2022 A.8.12",
    },
    {
        "match": lambda c, rows: any(
            "c2" in (r.get("description") or "").lower()
            or "beacon" in (r.get("description") or "").lower()
            or "command" in (r.get("description") or "").lower()
            for r in rows
        ),
        "zone": 2,
        "action_type": "isolate_host",
        "description": "Network-isolate compromised endpoints exhibiting C2 activity",
        "recipient": "SOC",
        "deadline_hours": 0.5,
        "citation": "Essential Eight — Application Control",
    },
    {
        "match": lambda c, rows: (c.get("severity") or "").lower() == "critical",
        "zone": 3,
        "action_type": "regulatory_notification",
        "description": "Prepare mandatory breach notification under NDB Scheme (72h deadline)",
        "recipient": "Legal / Privacy Officer",
        "deadline_hours": 72,
        "citation": "Privacy Act 1988 Part IIIC — NDB Scheme",
    },
    {
        "match": lambda c, rows: len(rows) >= 20,
        "zone": 3,
        "action_type": "forensic_preservation",
        "description": "Preserve forensic evidence — disk images, memory dumps, log archives",
        "recipient": "DFIR Lead",
        "deadline_hours": 24,
        "citation": "ISO 27037:2012 §7",
    },
]

# Kill chain phase mapping from evidence keywords to canonical phase names.
_KC_KEYWORD_MAP: list[tuple[str, list[str]]] = [
    ("initial_access", ["phish", "spearphish", "credential", "brute", "login", "mfa"]),
    ("lateral_movement", ["rdp", "smb", "psexec", "wmi", "lateral", "pivot"]),
    ("execution", ["powershell", "cmd.exe", "wscript", "script", "invoke", "exec"]),
    ("persistence", ["scheduled task", "registry", "autorun", "cron", "startup"]),
    ("privilege_escalation", ["admin", "root", "elevation", "uac", "sudo", "lsass"]),
    ("collection", ["compress", "archive", "staging", "copy into", "select"]),
    ("exfiltration", ["exfil", "upload", "rclone", "backblaze", "outbound", "egress"]),
    ("command_and_control", ["c2", "beacon", "callback", "dns tunnel", "covert"]),
]


# ── Pipeline version stamp for bitemporal trace provenance ───────────────────
_PIPELINE_VERSION = "deep_analyze_pipeline.v3.2"

# Lazy-initialised singletons for bitemporal trace + TemporalRAG indexing.
# These are module-level so they survive across assessment runs within the
# same server process.  For production, swap with persistent backends.
_TRACE_STORE = None
_INCIDENT_INDEX = None


def _get_trace_store():
    global _TRACE_STORE
    if _TRACE_STORE is None:
        db_path = os.path.join(
            os.getenv('SESSION_PERSIST_DIR', 'data/sessions'),
            'decision_trace.db',
        )
        try:
            from src.analysis.bitemporal_dispatch_trace import SQLiteDecisionTraceStore
            _TRACE_STORE = SQLiteDecisionTraceStore(db_path)
            logger.info('Bitemporal decision trace: SQLite at %s', db_path)
        except Exception as _exc:
            logger.warning('SQLiteDecisionTraceStore unavailable (%s) — falling back to in-memory', _exc)
            from src.analysis.bitemporal_dispatch_trace import InMemoryDecisionTraceStore
            _TRACE_STORE = InMemoryDecisionTraceStore()
    return _TRACE_STORE


def _get_incident_index():
    global _INCIDENT_INDEX
    if _INCIDENT_INDEX is None:
        import os
        db_path = os.path.join(
            os.getenv('SESSION_PERSIST_DIR', 'data/sessions'),
            'incident_index.db',
        )
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        from src.analysis.temporal_rag_dispatch import SQLiteIncidentIndexStore
        _INCIDENT_INDEX = SQLiteIncidentIndexStore(db_path)
    return _INCIDENT_INDEX


def _enrich_and_dispatch_personas(
    assessment: dict,
    clusters: list[dict],
    rows: list[dict],
    tenant_id: str,
) -> None:
    """Stage 5d: enrich narratives, build framework register, generate
    per-persona dispatch payloads, and wrap in bitemporal trace."""
    # Build row lookup for cluster evidence
    row_lookup: dict[int, dict] = {}
    for r in rows:
        ri = r.get('row_index')
        if ri is not None:
            try:
                row_lookup[int(float(ri))] = r
            except (TypeError, ValueError):
                pass

    # Load tenant classification config (optional)
    tenant_class = None
    try:
        from src.config.tenant_data_classification import load_for_tenant
        tenant_class = load_for_tenant(tenant_id)
    except Exception:
        pass

    # Import the new modules (lazy to avoid import errors if deps are missing)
    try:
        from src.llm.cluster_narrator_v2_schema import enrich_narrative
        from src.analysis.framework_mapper import build_control_failure_register
        from src.analysis.persona_dispatch import build_all_personas
        from src.analysis.bitemporal_dispatch_trace import (
            trace_persona_dispatch, find_superseded_decisions,
        )
        from src.analysis.temporal_rag_dispatch import (
            TemporalRAGProvider, _signature_from_narrative,
        )
    except Exception as exc:
        logger.warning("persona dispatch imports failed: %s", exc)
        return

    trace_store = _get_trace_store()
    incident_index = _get_incident_index()

    # Entity context for regulatory trigger evaluation
    entity_context = assessment.get('entity_context') or {}

    dispatch_ok = 0
    for cl in clusters:
        if not _is_breach_cluster(cl):
            continue

        # Gather cluster rows
        cl_rows = []
        for ref in (cl.get('row_refs') or []):
            try:
                k = int(float(ref))
                if k in row_lookup:
                    cl_rows.append(row_lookup[k])
            except (TypeError, ValueError):
                pass

        narrative = cl.get('llm_narrative') or cl.get('tier1_prefill') or {}
        if not isinstance(narrative, dict):
            narrative = {}

        # Step 1: Enrich the narrative with structured data
        narrative = enrich_narrative(
            narrative, cl, cl_rows,
            tenant_classification=tenant_class,
        )
        # Carry forward MITRE techniques from cluster if not in narrative,
        # then run inference from factor_tags / Diamond / kill-chain / DREAD fragments.
        if not narrative.get('mitre_techniques'):
            explicit = cl.get('mitre_techniques') or cl.get('mitre_tags') or []
            narrative['mitre_techniques'] = explicit
        # Always run inference when list is still empty (cluster.mitre_techniques is
        # often [] because it's set by the LLM narrator which may have been skipped).
        if not narrative.get('mitre_techniques'):
            try:
                from src.analysis.framework_mapper import _infer_mitre_from_cluster
                inferred = _infer_mitre_from_cluster(cl)
                if inferred:
                    narrative['mitre_techniques'] = inferred
                    # Write back so report endpoints and hopgraph can read it
                    cl['mitre_techniques'] = inferred
            except Exception as _mitre_err:
                logger.debug("MITRE inference failed for cluster %s: %s",
                             cl.get('cluster_id'), _mitre_err)

        # Stamp MITRE and cluster_id onto each evidence row so the Evidence UI
        # can display MITRE per-row and filter by cluster.
        cl_mitre = narrative.get('mitre_techniques') or cl.get('mitre_techniques') or []
        cluster_id_stamp = cl.get('cluster_id') or ''
        if cl_mitre or cluster_id_stamp:
            for ref in (cl.get('row_refs') or []):
                try:
                    k = int(float(ref))
                    if k in row_lookup:
                        row = row_lookup[k]
                        if cl_mitre and not row.get('mitre_technique'):
                            row['mitre_technique'] = cl_mitre[0]
                        if cl_mitre and not row.get('mitre_techniques'):
                            row['mitre_techniques'] = cl_mitre
                        if cluster_id_stamp and not row.get('correlation_cluster_id'):
                            row['correlation_cluster_id'] = cluster_id_stamp
                except (TypeError, ValueError):
                    pass

        # Carry forward Stage 5k compliance violations + Stage 5g+ ML scores
        # so build_persona_dispatch can inject them into LLM prompts.
        if cl.get('compliance_violations'):
            narrative.setdefault('compliance_violations', cl['compliance_violations'])
        if cl.get('_ml_scores'):
            narrative.setdefault('_ml_scores', cl['_ml_scores'])
        if cl.get('factor_tags'):
            narrative.setdefault('factor_tags', cl['factor_tags'])

        # Step 3: Build control failure register — pass cluster for MITRE inference
        register = build_control_failure_register(
            narrative, evidence_rows=cl_rows, entity_context=entity_context,
            cluster=cl,
        )
        cl['control_failure_register'] = register

        # Step 2+5: Build per-persona dispatch payloads with optional RAG
        rag = None
        try:
            rag = TemporalRAGProvider(
                incident_store=incident_index,
                decision_store=trace_store,
                tenant_id=tenant_id,
            )
        except Exception:
            pass

        # Assert cluster deterministic verdict into narrative when it ranks higher
        # than the LLM narrative verdict (which defaults to REQUIRES_INVESTIGATION
        # when the narrator falls back or is skipped).  Without this, audit persona
        # always says "Unqualified opinion" even for VALIDATED_BREACH clusters.
        cl_verdict = str(cl.get('verdict') or '')
        narrative_verdict = str(narrative.get('verdict') or '')
        if _VERDICT_RANK.get(cl_verdict, 0) > _VERDICT_RANK.get(narrative_verdict, 0):
            narrative['verdict'] = cl_verdict
            narrative['confidence'] = max(
                float(narrative.get('confidence') or 0.5),
                float(cl.get('confidence') or 0.7),
            )

        cluster_id = cl.get('cluster_id') or '?'
        payloads = build_all_personas(
            narrative,
            register=register,
            evidence_rows=cl_rows,
            cluster_id=cluster_id,
            rag_provider=rag,
        )

        # Step 4: Wrap each persona dispatch in bitemporal trace
        cl['persona_dispatch'] = {}
        for persona_key, payload in payloads.items():
            try:
                prior = find_superseded_decisions(
                    store=trace_store,
                    cluster_id=cluster_id,
                    persona=persona_key,
                    tenant_id=tenant_id,
                )
                decision = trace_persona_dispatch(
                    payload=payload,
                    narrative=narrative,
                    rows=cl_rows,
                    cluster_id=cluster_id,
                    tenant_id=tenant_id,
                    framework_version=_PIPELINE_VERSION,
                    supersedes=[d.decision_id for d in prior],
                )
                trace_store.put(decision)
                cl['persona_dispatch'][persona_key] = {
                    'decision_id': decision.decision_id,
                    'transaction_time': decision.transaction_time,
                    'supersedes': decision.supersedes,
                    **payload,
                }
            except Exception as trace_err:
                logger.debug("bitemporal trace failed for %s/%s: %s",
                             cluster_id, persona_key, trace_err)
                cl['persona_dispatch'][persona_key] = payload

        # Step 5: Index for TemporalRAG retrieval
        try:
            sig = _signature_from_narrative(narrative)
            summary = (narrative.get('attack_narrative') or
                       narrative.get('ioc_summary') or '')[:300]
            incident_index.index_incident(
                tenant_id=tenant_id,
                cluster_id=cluster_id,
                signature=sig,
                valid_time_start=(narrative.get('discovery') or {}).get('first_evidence_at') or '',
                valid_time_end=(narrative.get('discovery') or {}).get('when') or '',
                transaction_time=datetime.datetime.utcnow().isoformat(),
                narrative_summary=summary,
                outcome_summary=cl.get('final_verdict'),
            )
        except Exception as idx_err:
            logger.debug("TemporalRAG indexing failed for %s: %s", cluster_id, idx_err)

        # Store enriched narrative back to cluster
        cl['llm_narrative'] = narrative
        dispatch_ok += 1

    logger.info("Stage 5d: persona dispatch completed for %d breach clusters", dispatch_ok)


def _seed_proposed_actions_and_kill_chain(
    assessment: dict,
    clusters: list[dict],
    rows: list[dict],
) -> None:
    """Seed deterministic proposed_actions and kill_chain from breach clusters.

    Runs after LLM enrichment so prefill data is available. Only triggers for
    confirmed/validated breach clusters to avoid noise.
    """
    breach_clusters = [c for c in clusters if _is_breach_cluster(c)]
    if not breach_clusters:
        return

    # Build row lookup
    row_map: dict[int, dict] = {}
    for r in rows:
        ri = r.get("row_index")
        if ri is not None:
            try:
                row_map[int(float(ri))] = r
            except (TypeError, ValueError):
                pass

    # ── Proposed actions ──────────────────────────────────────────────────────
    proposed: list[dict] = []
    seen_types: set[str] = set()
    for cl in breach_clusters:
        cl_rows = []
        for ref in cl.get("row_refs") or []:
            try:
                k = int(float(ref))
                if k in row_map:
                    cl_rows.append(row_map[k])
            except (TypeError, ValueError):
                pass
        for tmpl in _ACTION_TEMPLATES:
            if tmpl["action_type"] in seen_types:
                continue
            try:
                if tmpl["match"](cl, cl_rows):
                    token = f"appr-{uuid.uuid4().hex[:12]}"
                    proposed.append({
                        "action_id": f"act-{uuid.uuid4().hex[:8]}",
                        "zone": tmpl["zone"],
                        "action_type": tmpl["action_type"],
                        "description": tmpl["description"],
                        "recipient": tmpl["recipient"],
                        "deadline_hours": tmpl["deadline_hours"],
                        "citation": tmpl["citation"],
                        "confidence": round(min(0.95, 0.6 + len(cl_rows) * 0.01), 2),
                        "evidence_count": len(cl_rows),
                        "status": "pending",
                        "approval_token": token,
                        "created_ts": time.time(),
                    })
                    seen_types.add(tmpl["action_type"])
            except Exception:
                pass
    assessment["proposed_actions"] = proposed

    # ── Kill chain ────────────────────────────────────────────────────────────
    kill_chain: list[dict] = []
    for cl in breach_clusters:
        cl_rows = []
        for ref in cl.get("row_refs") or []:
            try:
                k = int(float(ref))
                if k in row_map:
                    cl_rows.append(row_map[k])
            except (TypeError, ValueError):
                pass

        # Sort by timestamp if available
        def _ts_key(r: dict) -> str:
            return r.get("timestamp") or r.get("event_time") or r.get("date") or ""
        cl_rows.sort(key=_ts_key)

        for r in cl_rows[:20]:  # cap per cluster
            desc = " ".join(
                str(v)
                for v in [
                    r.get("description"),
                    r.get("event_name"),
                    r.get("eventName"),
                    r.get("action"),
                    r.get("process_name"),
                    r.get("process"),
                    r.get("command_line"),
                    r.get("cmdline"),
                    r.get("file_path"),
                    r.get("path"),
                    r.get("dest_host"),
                    r.get("dst_host"),
                    r.get("hostname"),
                    r.get("protocol"),
                    r.get("url"),
                    r.get("domain"),
                    r.get("query"),
                    r.get("threat_name"),
                ]
                if v
            ).lower()
            phase = "execution"  # default
            for ph, keywords in _KC_KEYWORD_MAP:
                if any(kw in desc for kw in keywords):
                    phase = ph
                    break
            actor = (
                r.get("user") or r.get("actor") or r.get("src_ip")
                or r.get("principal") or ""
            )
            kill_chain.append({
                "phase": phase,
                "timestamp": r.get("timestamp") or r.get("event_time") or "",
                "actor": actor,
                "action": r.get("description") or r.get("event_name") or "",
                "evidence_row_ids": [r.get("row_index", 0)],
                "mitre_techniques": [],
                "phase_id": f"kc-{uuid.uuid4().hex[:6]}",
                "enables_phase_id": None,
            })

    # Link causal pairs
    for i in range(len(kill_chain) - 1):
        kill_chain[i]["enables_phase_id"] = kill_chain[i + 1]["phase_id"]

    assessment["kill_chain"] = kill_chain


def _generate_deterministic_executive_summary(
    assessment: dict,
    clusters: list[dict],
    rows: list[dict],
) -> dict:
    """Build a no-LLM executive summary so persisted assessments are complete."""
    verdict_counts: dict[str, int] = {}
    for cluster in clusters:
        verdict = _cluster_verdict(cluster) or "UNKNOWN"
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1

    breach_clusters = [cluster for cluster in clusters if _is_breach_cluster(cluster)]
    benign_clusters = [
        cluster for cluster in clusters
        if _cluster_verdict(cluster) in {"BENIGN_EXPECTED", "INSUFFICIENT_EVIDENCE"}
    ]
    top_cluster = max(
        clusters,
        key=lambda cluster: (
            _VERDICT_RANK.get(_cluster_verdict(cluster), 0),
            str(cluster.get("severity") or "").lower() == "critical",
            _cluster_row_count(cluster),
            float(cluster.get("confidence") or 0),
        ),
        default={},
    )
    top_verdict = _cluster_verdict(top_cluster) or "UNKNOWN"
    top_name = (
        top_cluster.get("incident_name")
        or top_cluster.get("lead_description")
        or top_cluster.get("reason_summary")
        or "No lead cluster"
    )
    total_rows = (
        (assessment.get("evidence_store") or {}).get("row_count")
        or assessment.get("rows_processed")
        or len(rows or [])
    )
    source_count = (
        assessment.get("source_count")
        or len((assessment.get("source_counts") or {}).keys())
        or len({
            str(row.get("_source") or row.get("source") or row.get("source_file") or "")
            for row in rows
            if isinstance(row, dict) and (row.get("_source") or row.get("source") or row.get("source_file"))
        })
    )

    headline = (
        "Validated breach evidence identified"
        if any(_cluster_verdict(c) in {"VALIDATED_BREACH", "CONFIRMED_BREACH", "CONFIRMED_INTRUSION"} for c in breach_clusters)
        else "Security investigation requires review"
        if breach_clusters
        else "No validated breach cluster identified"
    )
    subline = (
        f"{len(breach_clusters)} breach-relevant cluster(s), {len(benign_clusters)} benign/expected cluster(s), "
        f"{int(total_rows or 0):,} event(s), {int(source_count or 0)} source(s)."
    )

    # ── Evidence-grounded narrative facts ───────────────────────────────────
    # Extract concrete entities so analysts see "wei.zhang from AS4134 (CN)
    # exfiltrated to sinobiz-sg.com" instead of "Lead cluster: ..." abstractions.
    from collections import Counter as _Counter
    _user_counter: _Counter = _Counter()
    _ext_domain_counter: _Counter = _Counter()
    _country_counter: _Counter = _Counter()
    _asn_counter: _Counter = _Counter()
    _high_risk_users: set[str] = set()
    _top_evidence_rows: list[dict] = []
    _breach_factor_counter: _Counter = _Counter()

    for _r in (rows or []):
        if not isinstance(_r, dict):
            continue
        _u = str(_r.get("user_canonical") or _r.get("user") or "").strip().lower()
        if _u and _u not in ("-", "n/a", "system", "root", ""):
            _user_counter[_u] += 1
        _dom = str(
            _r.get("external_recipient_domain") or _r.get("dst_host") or
            _r.get("resp_h") or _r.get("destination_host") or ""
        ).strip().lower()
        if _dom and "." in _dom:
            _ext_domain_counter[_dom] += 1
        _ctry = str(_r.get("country") or _r.get("src_country") or "").strip().upper()
        if _ctry and len(_ctry) == 2:
            _country_counter[_ctry] += 1
        _asn = str(_r.get("asn") or _r.get("src_asn") or "").strip().upper()
        if _asn.startswith("AS"):
            _asn_counter[_asn] += 1
        if str(_r.get("_geopolitical_risk") or "") == "high" and _u:
            _high_risk_users.add(_u)

    # Top-3 high-triage evidence rows for direct citation
    try:
        _top_evidence_rows = sorted(
            (r for r in (rows or []) if isinstance(r, dict)),
            key=lambda r: float(r.get("triage_score") or 0.0),
            reverse=True,
        )[:3]
    except Exception:
        _top_evidence_rows = []

    _top_users = [u for u, _ in _user_counter.most_common(3)]
    _top_domains = [d for d, _ in _ext_domain_counter.most_common(3)]
    _top_countries = [c for c, _ in _country_counter.most_common(3)]
    _top_asns = [a for a, _ in _asn_counter.most_common(3)]
    for _bc in breach_clusters:
        for _f in (_bc.get("factor_tags") or []) + (_bc.get("_chrono_factors") or []):
            if _f:
                _breach_factor_counter[str(_f)] += 1
    _top_factors = [f for f, _ in _breach_factor_counter.most_common(12)]

    # Aggregate compliance violations across breach clusters → top-level field.
    _compliance_lines: list[str] = []
    _compliance_violations: list[dict] = []
    _seen_controls: set[str] = set()
    for _bc in breach_clusters:
        _reg = _bc.get("control_failure_register") or {}
        _by_fw = _reg.get("control_failures_by_framework") or {}
        if isinstance(_by_fw, dict):
            for _fw, _ctrls in _by_fw.items():
                if _fw == "unmapped_techniques" or not isinstance(_ctrls, list):
                    continue
                for _c in _ctrls:
                    if not isinstance(_c, dict):
                        continue
                    _cid = str(_c.get("control_id") or _c.get("id") or "")
                    _key = f"{_fw}:{_cid}"
                    if _cid and _key not in _seen_controls:
                        _seen_controls.add(_key)
                        _compliance_violations.append({
                            "framework": _fw,
                            "control_id": _cid,
                            "title": _c.get("title") or _c.get("control_title") or "",
                            "severity": _c.get("severity") or "medium",
                            "evidence_refs": _c.get("evidence_refs") or [],
                            "triggered_by": _c.get("triggered_by") or [],
                        })
    if _compliance_violations:
        _by_fw_summary: dict[str, int] = {}
        for _cv in _compliance_violations:
            _by_fw_summary[_cv["framework"]] = _by_fw_summary.get(_cv["framework"], 0) + 1
        _compliance_lines.append(
            "Compliance impact: " + ", ".join(
                f"{_n} {_fw} control(s)" for _fw, _n in sorted(_by_fw_summary.items())
            ) + "."
        )

    # Build narrative paragraph
    _narrative_parts: list[str] = [
        f"{headline}. Lead cluster: {str(top_name)[:180]} "
        f"(verdict {top_verdict}, {_cluster_row_count(top_cluster)} evidence row(s))."
    ]
    if _top_users:
        _user_str = ", ".join(_top_users)
        if _high_risk_users & set(_top_users):
            _narrative_parts.append(
                f"Principal actors: {_user_str} "
                f"({len(_high_risk_users & set(_top_users))} on high-risk geopolitical infrastructure)."
            )
        else:
            _narrative_parts.append(f"Principal actors: {_user_str}.")
    if _top_asns or _top_countries:
        _infra_bits = []
        if _top_asns:
            _infra_bits.append("ASN " + "/".join(_top_asns))
        if _top_countries:
            _infra_bits.append("country " + "/".join(_top_countries))
        _narrative_parts.append("Source infrastructure: " + ", ".join(_infra_bits) + ".")
    if _top_domains:
        _narrative_parts.append(
            f"External destinations: {', '.join(_top_domains)}."
        )
    if _top_factors:
        _narrative_parts.append("Material signals: " + ", ".join(_top_factors) + ".")
    if _top_evidence_rows:
        _ev_bits = []
        for _ev in _top_evidence_rows:
            _ts = str(_ev.get("timestamp") or _ev.get("ts") or "").split(".")[0][:19]
            _evt = str(_ev.get("event_type") or _ev.get("Operation") or _ev.get("event_name") or "event")[:40]
            _u = str(_ev.get("user_canonical") or _ev.get("user") or "")[:40]
            _ev_bits.append(f"{_ts} {_evt}{' by ' + _u if _u else ''}")
        _narrative_parts.append("Top evidence: " + " | ".join(_ev_bits) + ".")
    _narrative_parts.extend(_compliance_lines)
    _narrative_parts.append(
        "Verdict distribution: " +
        (', '.join(f'{k}={v}' for k, v in sorted(verdict_counts.items())) or 'none') + "."
    )
    body = " ".join(_narrative_parts)

    return {
        "headline": headline,
        "subline": subline,
        "executive_summary": body,
        "deterministic": "\n".join([headline, subline, body]),
        "generated_at": int(time.time()),
        "from_cache": False,
        "narrative_provenance": "assessment_worker_deterministic",
        "narrative_source": "deterministic_pipeline",
        "scope": {
            "breach_clusters": len(breach_clusters),
            "benign_clusters": len(benign_clusters),
            "total_clusters": len(clusters),
            "total_rows": int(total_rows or 0),
            "source_count": int(source_count or 0),
            "principal_users": _top_users,
            "external_destinations": _top_domains,
            "source_countries": _top_countries,
            "source_asns": _top_asns,
            "high_risk_users": sorted(_high_risk_users),
            "top_factors": _top_factors,
        },
        "verdict_counts": verdict_counts,
        "compliance_violations": _compliance_violations,
    }


def _persist_assessment_json(assessment_id: str, org: str, data: dict) -> str | None:
    """Write assessment JSON to the same path structure used by the sync handler."""
    try:
        repo_root = os.getcwd()
        datepart = datetime.datetime.utcnow().strftime("%Y-%m-%d")
        base = os.getenv("SESSION_PERSIST_DIR") or os.path.join(repo_root, "data", "assessments")
        dest = os.path.join(base, org or "unknown", datepart)
        os.makedirs(dest, exist_ok=True)
        path = os.path.join(dest, f"{assessment_id}.json")
        data["persisted_path"] = path
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(data, default=str))
        os.replace(tmp, path)

        # Also register in REPORT_STORE so the existing GET /assessments/{id}
        # endpoint can serve it without needing a DB-backed lookup.
        try:
            from src.api.deep_analyze_endpoints import REPORT_STORE
            REPORT_STORE[assessment_id] = data
        except Exception:
            pass

        return path
    except Exception as exc:
        logger.warning("persist_assessment_json failed for %s: %s", assessment_id, exc)
        return None


# ── Background worker loop ────────────────────────────────────────────────────

async def _worker_loop() -> None:
    """Consume jobs from _INGEST_QUEUE indefinitely."""
    logger.info("ingest_worker: started, waiting for jobs")
    while True:
        assessment_id = None
        try:
            job = await _INGEST_QUEUE.get()
            if job is None:  # sentinel — shutdown signal
                logger.info("ingest_worker: received shutdown sentinel")
                break
            assessment_id = job["assessment_id"]
            org = job.get("org", "unknown")
            file_paths = job.get("file_paths", [])
            progress_fn = job.get("progress_fn", _noop_progress)

            # Skip if the job was cancelled while waiting in the queue.
            try:
                from src.core.ingest import store as _store_chk
                _job_status = (_store_chk.get_job(assessment_id) or {}).get("status", "")
                if _job_status == "cancelled":
                    logger.info("ingest_worker: skipping cancelled job %s", assessment_id)
                    continue
            except Exception:
                pass
            logger.info("ingest_worker: starting job %s (%d files)", assessment_id, len(file_paths))
            await run_assessment_pipeline(
                assessment_id,
                org,
                file_paths,
                progress_fn=progress_fn,
            )
        except asyncio.CancelledError:
            break
        except Exception:
            logger.exception("ingest_worker: unhandled error in job loop")
        finally:
            # Remove from active set so the same assessment_id can be re-queued
            # if explicitly reprocessed (e.g. after a failure and recovery).
            if assessment_id:
                _ACTIVE_JOB_IDS.discard(assessment_id)
            try:
                _INGEST_QUEUE.task_done()
            except Exception:
                pass


_worker_task: asyncio.Task | None = None


def _recover_queued_jobs() -> int:
    try:
        from src.core.ingest import store as _store
        jobs = _store.list_recoverable_jobs()
    except Exception:
        logger.debug("ingest_worker: queued job recovery lookup failed", exc_info=True)
        return 0
    recovered = 0
    for job in jobs:
        aid = str(job.get("assessment_id") or "")
        if not aid:
            continue
        files = _store.raw_files_for(aid)
        files = [(path, name) for path, name in files if path and os.path.exists(path)]
        if not files:
            try:
                _store.update_job(aid, status="failed", stage="recovery", error="Queued job has no recoverable raw files")
            except Exception:
                pass
            continue
        try:
            _store.update_job(aid, status="queued", stage="queued", stage_label="Recovered queued job")
            enqueue_job(aid, str(job.get("org") or "unknown"), files)
            recovered += 1
        except Exception:
            logger.debug("ingest_worker: failed to recover queued job %s", aid, exc_info=True)
    return recovered


def start_worker(app=None) -> None:
    """Start the background worker task — called from app lifespan."""
    global _worker_task
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        logger.warning("ingest_worker: no running event loop at start_worker call")
        return
    if _worker_task is None or _worker_task.done():
        _worker_task = loop.create_task(_worker_loop(), name="ingest_worker")
        logger.info("ingest_worker: task created")
        recovered = _recover_queued_jobs()
        if recovered:
            logger.info("ingest_worker: recovered %d queued job(s)", recovered)


def stop_worker() -> None:
    """Send shutdown sentinel to the worker queue."""
    try:
        _INGEST_QUEUE.put_nowait(None)
    except Exception:
        pass


def enqueue_job(
    assessment_id: str,
    org: str,
    file_paths: list[tuple[str, str]],
    *,
    progress_fn: ProgressFn = _noop_progress,
) -> None:
    """Post a job to the ingest queue — idempotent for the same assessment_id."""
    if assessment_id in _ACTIVE_JOB_IDS:
        logger.debug("ingest_worker: job %s already queued/running — skipping duplicate enqueue", assessment_id)
        return
    _ACTIVE_JOB_IDS.add(assessment_id)
    job = {
        "assessment_id": assessment_id,
        "org": org,
        "file_paths": file_paths,
        "progress_fn": progress_fn,
    }
    try:
        _INGEST_QUEUE.put_nowait(job)
    except asyncio.QueueFull:
        _ACTIVE_JOB_IDS.discard(assessment_id)
        logger.error("ingest queue full — job %s dropped", assessment_id)
