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
    row.setdefault("source_type", raw.get("_source_type", ""))

    row["triage_score"] = _score_async_ingest_row(raw, row)
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


def _score_async_ingest_row(raw: dict, normalized: dict) -> float:
    sev = str(raw.get("severity") or raw.get("risk_level") or raw.get("alert_severity") or "").lower()
    score = {
        "critical": 0.95,
        "high": 0.75,
        "medium": 0.35,
        "low": 0.10,
        "info": 0.03,
        "informational": 0.03,
    }.get(sev, 0.05)

    # Elevate security-relevant cloud/IAM events above the triage threshold.
    # BAU events (SELECT queries, ListBuckets, routine file access) are NOT
    # elevated — they form single-source noise clusters at scale.
    source_type = str(normalized.get("_source_type") or "").lower()
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
    return float(max(0.0, min(1.0, score)))


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

        from src.core.ingest.file_parser import parse_file
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

            batch: list[dict] = []
            try:
                for row in parse_file(path, filename=filename):
                    norm = _normalize_ingest_row(row, total_rows)
                    # Tag every row with its evidence lane for downstream policy enforcement.
                    norm.setdefault("_lane", file_lane)

                    # ── Stage 1b: file-sensitivity tagging ───────────────────────
                    _SENSITIVE_PATH_TOKENS = (
                        "payroll", "acquisition", "merger", "novabridge", "ip-schedule",
                        "infra-map", "capex", "q1-projections", "ceo", "board",
                        "ma-document", "merger-ip", "novabridge-acquisition",
                        "critical-infra", "critical_infra",
                    )
                    _obj = str(
                        norm.get("ObjectId") or norm.get("object_id") or
                        norm.get("file_path") or norm.get("resource") or ""
                    ).lower()
                    if any(tok in _obj for tok in _SENSITIVE_PATH_TOKENS):
                        norm.setdefault("_sensitivity", "high")
                        norm["triage_score"] = max(norm.get("triage_score") or 0.0, 0.65)

                    # ── Stage 1b: external_recipient_domain tagging for email rows ──
                    _own_tld = (".com.au", ".gov.au", ".net.au", ".org.au")
                    for _rec_fld in ("Recipients", "recipients"):
                        _recs = norm.get(_rec_fld)
                        if not _recs:
                            continue
                        if isinstance(_recs, str):
                            _recs = [_recs]
                        for _rec in _recs[:4]:
                            _dom = str(_rec).split("@")[-1].lower().strip() if "@" in str(_rec) else ""
                            if _dom and "." in _dom and not any(_dom.endswith(t) for t in _own_tld):
                                norm.setdefault("external_recipient_domain", _dom)
                                norm["triage_score"] = max(norm.get("triage_score") or 0.0, 0.25)
                                break
                    _fwd = str(norm.get("ForwardingSmtpAddress") or norm.get("forwarding_smtp") or "").strip()
                    if "@" in _fwd:
                        _fdom = _fwd.split("@")[-1].lower()
                        if not any(_fdom.endswith(t) for t in _own_tld):
                            norm.setdefault("external_recipient_domain", _fdom)
                            norm["triage_score"] = max(norm.get("triage_score") or 0.0, 0.65)

                    batch.append(norm)
                    total_rows += 1
                    if len(batch) >= PARSE_BATCH_SIZE:
                        await asyncio.to_thread(_store.persist_row_batch, assessment_id, batch)
                        batch = []
                        _progress("parsing", file_pct, f"Parsed {total_rows:,} rows from {filename}…")
                if batch:
                    await asyncio.to_thread(_store.persist_row_batch, assessment_id, batch)
            except Exception as exc:
                logger.warning("parse failed for %s in job %s: %s", filename, assessment_id, exc)

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
                    _ei_ok += 1
                except Exception as _ei_err:
                    logger.warning('cluster intelligence enrichment failed for %s: %s', _cl.get('cluster_id'), _ei_err, exc_info=True)
            logger.info('Stage 5c: enriched %d/%d clusters, lookup_size=%d', _ei_ok, len(clusters), len(_row_lookup_ei))
            _progress('reasoning', 73, f'Cluster intelligence enrichments complete ({_ei_ok} clusters)')
        except Exception as exc:
            logger.warning('cluster intelligence enrichment stage failed for %s: %s', assessment_id, exc, exc_info=True)

        if clusters:
            _progress("reasoning", 72, "Generating LLM narratives for top clusters")
            # Cap narration at 90s for background ingest — avoids blocking the queue
            # for many minutes when Ollama is under load. Deterministic enrichments
            # (DREAD, SABSA, cluster intelligence) already ran above and are preserved.
            _narrate_timeout = float(os.getenv("JANUSEC_INGEST_NARRATE_TIMEOUT_S", "90"))
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
                    "cluster narration timed out (>%.0fs) for %s — using fallback narratives",
                    _narrate_timeout, assessment_id,
                )
            except Exception as exc:
                logger.warning("cluster narration failed for %s: %s", assessment_id, exc)

        # ── Stage 5d: persona dispatch + framework mapping + bitemporal trace ──
        # Enriches each breach cluster's narrative with structured data (affected
        # principals, data sensitivity, attacker infra), builds the control
        # failure register, generates per-persona dispatch payloads, and wraps
        # each in a bitemporal decision trace for audit replay.
        _progress("reasoning", 78, "Building persona dispatch payloads")
        try:
            _enrich_and_dispatch_personas(assessment, clusters, filtered_rows, org)
        except Exception as exc:
            logger.warning("persona dispatch stage failed for %s: %s", assessment_id, exc, exc_info=True)

        # ── Stage 5e: index evidence rows into TemporalRAG ───────────────────
        # This ensures the exec summary's evidence_frame module can retrieve
        # time-windowed neighbours per cluster from the TemporalRAG engine.
        try:
            from src.ai.temporal_rag import get_engine as _get_rag_engine
            _rag = _get_rag_engine()
            if _rag is not None:
                _rag_count = _rag.index_rows(filtered_rows, tenant=org)
                logger.info("Stage 5e: indexed %d rows into TemporalRAG for %s", _rag_count, assessment_id)
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
        # then fall back to inference from Diamond/kill-chain/DREAD fragments.
        if not narrative.get('mitre_techniques'):
            explicit = cl.get('mitre_techniques') or cl.get('mitre_tags') or []
            narrative['mitre_techniques'] = explicit

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
    body = (
        f"{headline}. Lead cluster: {str(top_name)[:180]} "
        f"(verdict {top_verdict}, {_cluster_row_count(top_cluster)} evidence row(s)). "
        f"Verdict distribution: {', '.join(f'{k}={v}' for k, v in sorted(verdict_counts.items())) or 'none'}."
    )
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
        },
        "verdict_counts": verdict_counts,
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
