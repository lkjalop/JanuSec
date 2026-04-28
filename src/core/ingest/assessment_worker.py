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
        _breach_verdicts = {'VALIDATED_BREACH', 'CONFIRMED_BREACH', 'LIKELY_BREACH', 'LIKELY_COMPROMISE'}
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
                _verdict = str(_cl.get('verdict') or _cl.get('final_verdict') or '').upper()
                if _verdict not in _breach_verdicts:
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
                _verdict_ei = str(_cl.get('verdict') or _cl.get('final_verdict') or '').upper()
                if _verdict_ei not in _breach_verdicts:
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
            try:
                from src.core.ingest.cluster_narrator import narrate_top_clusters
                await asyncio.to_thread(
                    narrate_top_clusters,
                    clusters,
                    filtered_rows,
                    assessment_id=assessment_id,
                )
            except Exception as exc:
                logger.warning("cluster narration failed for %s: %s", assessment_id, exc)

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
        try:
            _seed_proposed_actions_and_kill_chain(assessment, clusters, filtered_rows)
            logger.info("Stage 6b: seeded proposed_actions=%d, kill_chain=%d for %s",
                        len(assessment.get('proposed_actions', [])),
                        len(assessment.get('kill_chain', [])),
                        assessment_id)
        except Exception as exc:
            logger.debug("proposed_actions/kill_chain seeding skipped for %s: %s", assessment_id, exc)

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
    ("execution", ["powershell", "cmd.exe", "wscript", "script", "invoke", "exec"]),
    ("persistence", ["scheduled task", "registry", "autorun", "cron", "startup"]),
    ("privilege_escalation", ["admin", "root", "elevation", "uac", "sudo", "lsass"]),
    ("lateral_movement", ["rdp", "smb", "psexec", "wmi", "lateral", "pivot"]),
    ("collection", ["compress", "archive", "staging", "copy into", "select"]),
    ("exfiltration", ["exfil", "upload", "rclone", "backblaze", "outbound", "egress"]),
    ("command_and_control", ["c2", "beacon", "callback", "dns tunnel", "covert"]),
]


def _seed_proposed_actions_and_kill_chain(
    assessment: dict,
    clusters: list[dict],
    rows: list[dict],
) -> None:
    """Seed deterministic proposed_actions and kill_chain from breach clusters.

    Runs after LLM enrichment so prefill data is available. Only triggers for
    confirmed/validated breach clusters to avoid noise.
    """
    breach_verdicts = {"VALIDATED_BREACH", "CONFIRMED_BREACH", "CONFIRMED_INTRUSION"}
    breach_clusters = [
        c for c in clusters
        if (c.get("verdict") or c.get("final_verdict") or "").upper() in breach_verdicts
    ]
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
            desc = (r.get("description") or r.get("event_name") or "").lower()
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
