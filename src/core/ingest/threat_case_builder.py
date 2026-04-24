"""Deterministic threat-case layering for async assessment ingest.

Raw correlation clusters are audit evidence and must remain intact.  The breach
UI can still present curated threat cases, but those cases are a view layered on
top of classified analysis clusters, not a replacement for them.

Evidence policy
---------------
Only rows with _lane == "telemetry_evidence" (or no _lane set, for backwards
compatibility with pre-provenance rows) may contribute to confirmed/suspicious
findings.  Business-context, evaluation-answer-key, platform-prior, llm-narrative,
and cache-or-history rows are ignored when building findings.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from src.core.ingest.input_classifier import (
    LANE_TELEMETRY_EVIDENCE,
    LANE_EVALUATION_ANSWER_KEY,
    LANE_LLM_NARRATIVE,
    LANE_CACHE_OR_HISTORY,
)

# Lanes that are BLOCKED from creating findings.  Telemetry rows with no _lane
# field are treated as telemetry evidence for backwards compatibility.
_BLOCKED_LANES: frozenset[str] = frozenset({
    LANE_EVALUATION_ANSWER_KEY,
    LANE_LLM_NARRATIVE,
    LANE_CACHE_OR_HISTORY,
    "business_context",
    "platform_prior",
})


def _is_evidence_row(row: dict) -> bool:
    """True when the row is allowed to create confirmed/suspicious findings."""
    lane = row.get("_lane") or ""
    return lane not in _BLOCKED_LANES


# ── Material pattern detectors ─────────────────────────────────────────────────
# Each detector is: (case_id, incident_name, case_role, verdict, severity,
#                    confidence, lead_description, headline_subtitle, terms)
# Terms are real TTP/tool keywords — no scenario names, no entity names.
_MATERIAL_PATTERNS = [
    {
        "case_id": "case-lsass-credential-theft",
        "incident_name": "LSASS Credential Theft",
        "case_role": "credential_theft",
        "verdict": "VALIDATED_BREACH",
        "severity": "critical",
        "confidence": 0.90,
        "lead_description": "LSASS process memory was accessed to harvest credential material.",
        "headline_subtitle": "Credential dumping from LSASS is a hallmark of privilege escalation and lateral movement.",
        "terms": ["lsass", "comsvcs", "mimikatz", "procdump", "ntds", "credential dumping", "credential dump"],
    },
    {
        "case_id": "case-rclone-exfiltration",
        "incident_name": "Rclone Cloud Exfiltration",
        "case_role": "data_exfiltration",
        "verdict": "VALIDATED_BREACH",
        "severity": "critical",
        "confidence": 0.88,
        "lead_description": "A file-sync tool was used to copy data to an external cloud destination.",
        "headline_subtitle": "Rclone or similar tools transferring data to unmanaged cloud storage indicate deliberate exfiltration.",
        "terms": ["rclone", "backblaze", "mega.nz", "b2 bucket", "external storage", "data exfil", "exfiltrat"],
    },
    {
        "case_id": "case-snowflake-unload",
        "incident_name": "Snowflake UNLOAD Data Movement",
        "case_role": "data_exfiltration",
        "verdict": "VALIDATED_BREACH",
        "severity": "critical",
        "confidence": 0.87,
        "lead_description": "Snowflake COPY INTO or UNLOAD commands moved bulk data to an external stage.",
        "headline_subtitle": "Bulk export from Snowflake to an external stage without DLP controls is a data-loss signal.",
        "terms": ["snowflake", "copy into", "external stage", "unload", "query_history", "stage"],
    },
    {
        "case_id": "case-k8s-container-escape",
        "incident_name": "K8s Privileged Container Escape",
        "case_role": "privilege_escalation",
        "verdict": "VALIDATED_BREACH",
        "severity": "critical",
        "confidence": 0.85,
        "lead_description": "A privileged Kubernetes container was launched, indicating a container escape attempt.",
        "headline_subtitle": "Privileged containers with host-path mounts or hostPID enable node-level compromise.",
        "terms": ["privileged container", "kubernetes", "k8s", "falco", "serviceaccount", "hostpid", "hostpath", "pod exec"],
    },
    {
        "case_id": "case-dns-beaconing",
        "incident_name": "Low-Reputation DNS Beaconing",
        "case_role": "c2_communication",
        "verdict": "VALIDATED_BREACH",
        "severity": "high",
        "confidence": 0.82,
        "lead_description": "Periodic DNS queries to low-reputation domains suggest command-and-control beaconing.",
        "headline_subtitle": "Regular NXDomain or low-reputation DNS traffic is a beacon pattern indicative of C2.",
        "terms": ["dns beacon", "nxdomain", "low reputation", "low-reputation", "periodic dns", "c2 beacon", "command.and.control"],
    },
]

# Generic threat-case templates — matched when no material pattern fires.
_CASE_DEFS = [
    {
        "case_id": "case-primary-breach",
        "incident_name": "PRIMARY BREACH",
        "case_role": "primary_breach",
        "verdict": "VALIDATED_BREACH",
        "severity": "critical",
        "confidence": 0.85,
        "lead_description": "Correlated evidence indicates a validated breach or active intrusion.",
        "headline_subtitle": "Multiple attack phases observed across identity, endpoint, and network telemetry.",
        "terms": [
            "lsass", "comsvcs", "mimikatz", "procdump", "ntds",
            "rclone", "mega.nz", "external stage", "copy into",
            "lateral movement", "privilege escalation", "data exfil",
            "impossible travel", "credential dumping",
        ],
    },
    {
        "case_id": "case-authorized-test",
        "incident_name": "AUTHORIZED SECURITY TEST",
        "case_role": "authorized_test",
        "verdict": "BENIGN_EXPECTED",
        "severity": "low",
        "confidence": 0.82,
        "lead_description": "Activity matches an authorized penetration test or red team engagement.",
        "headline_subtitle": "Pentest tooling is expected within the authorized engagement scope.",
        "terms": [
            "pentest", "red team", "authorized test", "cobalt strike",
            "scope of work", "sow", "engagement",
        ],
    },
    {
        "case_id": "case-approved-travel",
        "incident_name": "APPROVED OVERSEAS ACCESS",
        "case_role": "approved_travel",
        "verdict": "BENIGN_EXPECTED",
        "severity": "low",
        "confidence": 0.78,
        "lead_description": "Login from an overseas location matches pre-approved travel.",
        "headline_subtitle": "Travel context explains the apparent geo-anomaly — no compromise evidence found.",
        "terms": [
            "approved travel", "travel request", "business trip",
            "travel notification", "overseas access", "plausible travel",
        ],
    },
]


def _row_text(row: dict) -> str:
    try:
        return " ".join(str(v) for v in row.values()).lower()
    except Exception:
        return str(row).lower()


def _cluster_rows(cluster: dict, row_by_idx: dict[int, dict]) -> list[dict]:
    refs = cluster.get("row_refs") or cluster.get("rows") or []
    out = []
    for ref in refs:
        try:
            idx = int(ref)
        except Exception:
            continue
        row = row_by_idx.get(idx)
        if row:
            out.append(row)
    return out


def _top_rows(rows: list[dict], limit: int) -> list[dict]:
    return sorted(
        rows,
        key=lambda r: float(r.get("triage_score") or 0),
        reverse=True,
    )[:limit]


def build_threat_cases(
    clusters: list[dict],
    evidence_rows: list[dict],
    *,
    evidence_cap: int = 80,
) -> dict[str, list[dict]]:
    """Build raw -> analysis -> threat-case layers without losing clusters."""
    raw_clusters = [dict(c) for c in clusters]
    analysis_clusters = _build_analysis_clusters(raw_clusters, evidence_rows)
    threat_cases = _build_presentation_cases(analysis_clusters, evidence_rows, evidence_cap=evidence_cap)
    return {
        "raw_correlation_clusters": raw_clusters,
        "analysis_clusters": analysis_clusters,
        "threat_cases": threat_cases,
    }


def _build_analysis_clusters(clusters: list[dict], evidence_rows: list[dict]) -> list[dict]:
    row_by_idx = {}
    for row in evidence_rows:
        try:
            row_by_idx[int(row.get("row_index"))] = row
        except Exception:
            continue

    out: list[dict[str, Any]] = []
    for cluster in clusters:
        item = dict(cluster)
        refs = []
        for ref in item.get("row_refs") or item.get("rows") or []:
            try:
                refs.append(int(ref))
            except Exception:
                continue
        # Only use evidence rows for classification text — not blocked-lane rows.
        evidence_ref_rows = [row_by_idx[r] for r in refs[:100] if r in row_by_idx and _is_evidence_row(row_by_idx[r])]
        text = " ".join(
            [
                str(item.get("lead_description") or ""),
                str(item.get("reason_summary") or ""),
                " ".join(_row_text(r) for r in evidence_ref_rows),
            ]
        ).lower()
        classification = "unclassified"
        if any(term in text for term in ("lsass", "credential dumping", "rclone", "data exfil", "external stage", "copy into", "privilege escalation", "beacon")):
            classification = "suspicious_unconfirmed"
        if any(term in text for term in ("validated breach", "confirmed breach", "confirmed malicious")):
            classification = "confirmed_breach"
        if any(term in text for term in ("authorized test", "authorised test", "pentest", "red team", "scope of work")):
            classification = "authorized_activity"
        if any(term in text for term in ("approved travel", "travel approval", "benign", "false positive")):
            classification = "benign_flagged"
        if any(term in text for term in ("containment", "blocked", "isolated", "response")):
            classification = "response_in_progress"

        item["row_refs"] = sorted(set(refs))
        item["row_count"] = int(item.get("row_count") or len(item["row_refs"]))
        item["analysis_classification"] = classification
        item["confidence_calibration"] = "uncalibrated"
        item.setdefault("confidence", min(0.95, 0.35 + (item["row_count"] / 200.0)))
        out.append(item)
    return out


def _build_presentation_cases(
    clusters: list[dict],
    evidence_rows: list[dict],
    *,
    evidence_cap: int = 80,
) -> list[dict]:
    """Group analysis clusters for presentation while preserving source links.

    Evidence policy: only rows with _lane == telemetry_evidence (or no _lane)
    may contribute to confirmed/suspicious findings.  Blocked-lane rows are
    excluded from term matching so they cannot create AUTHORIZED SECURITY TEST,
    APPROVED OVERSEAS ACCESS, or PRIMARY BREACH cases.
    """
    # Split rows by lane so that blocked-lane rows cannot create findings.
    telemetry_rows = [r for r in evidence_rows if _is_evidence_row(r)]

    row_by_idx = {}
    for row in evidence_rows:
        try:
            row_by_idx[int(row.get("row_index"))] = row
        except Exception:
            continue

    cluster_texts: dict[str, str] = {}
    cluster_rows: dict[str, list[dict]] = {}
    for cluster in clusters:
        cid = str(cluster.get("cluster_id") or "")
        rows = _cluster_rows(cluster, row_by_idx)
        # Only evidence rows contribute to pattern matching text.
        evidence_cluster_rows = [r for r in rows if _is_evidence_row(r)]
        cluster_rows[cid] = evidence_cluster_rows
        cluster_texts[cid] = " ".join(
            [
                str(cluster.get("lead_description") or ""),
                str(cluster.get("reason_summary") or ""),
                " ".join(_row_text(r) for r in evidence_cluster_rows[:250]),
            ]
        ).lower()

    assigned_clusters: set[str] = set()
    assigned_rows: set[int] = set()
    cases: list[dict[str, Any]] = []

    # ── Pass 1: material pattern detectors (rank above generic case defs) ─────
    for spec in _MATERIAL_PATTERNS:
        terms = [t.lower() for t in spec["terms"]]
        matched_clusters = [
            cid for cid, text in cluster_texts.items()
            if any(term in text for term in terms)
        ]
        # Only scan telemetry rows for term matching — never blocked-lane rows.
        matched_rows = [
            row for row in telemetry_rows
            if any(term in _row_text(row) for term in terms)
        ]
        row_refs = sorted({
            int(row.get("row_index"))
            for row in matched_rows
            if row.get("row_index") is not None
        })
        for cid in matched_clusters:
            assigned_clusters.add(cid)
            for row in cluster_rows.get(cid, []):
                try:
                    row_refs.append(int(row.get("row_index")))
                except Exception:
                    pass
        row_refs = sorted(set(row_refs))
        if not row_refs and not matched_clusters:
            continue

        assigned_rows.update(row_refs)
        evidence_preview = _top_rows(
            [row_by_idx[i] for i in row_refs if i in row_by_idx],
            evidence_cap,
        )
        cases.append({
            "cluster_id": spec["case_id"],
            "case_id": spec["case_id"],
            "incident_name": spec["incident_name"],
            "case_role": spec["case_role"],
            "verdict": spec["verdict"],
            "final_verdict": spec["verdict"],
            "severity": spec["severity"],
            "confidence": spec["confidence"],
            "confidence_calibration": "uncalibrated",
            "lead_description": spec["lead_description"],
            "headline_subtitle": spec["headline_subtitle"],
            "row_refs": row_refs,
            "row_count": len(row_refs),
            "supporting_cluster_ids": matched_clusters,
            "evidence_preview": evidence_preview,
            "tier1_prefill": {
                "incident_name": spec["incident_name"],
                "headline_subtitle": spec["headline_subtitle"],
                "short_narrative": spec["lead_description"],
                "what_happened": spec["lead_description"],
                "confidence_meter": {"total": int(spec["confidence"] * 100), "segments": {}},
                "top_actions": [],
                "mitre_techniques": [],
                "verdict_reasoning": "",
                "mitre_evidence_map": {},
            },
        })

    # ── Pass 2: generic case defs for patterns not caught above ───────────────
    material_case_ids = {c["case_id"] for c in cases}
    for spec in _CASE_DEFS:
        # Skip if a material pattern already produced this role (avoid duplicates).
        if any(c.get("case_role") == spec.get("case_role") for c in cases):
            continue
        terms = [t.lower() for t in spec["terms"]]
        matched_clusters = [
            cid for cid, text in cluster_texts.items()
            if cid not in assigned_clusters and any(term in text for term in terms)
        ]
        # Only scan telemetry rows — never blocked-lane rows.
        matched_rows = [
            row for row in telemetry_rows
            if any(term in _row_text(row) for term in terms)
        ]
        row_refs = sorted({
            int(row.get("row_index"))
            for row in matched_rows
            if row.get("row_index") is not None
        })
        for cid in matched_clusters:
            assigned_clusters.add(cid)
            for row in cluster_rows.get(cid, []):
                try:
                    row_refs.append(int(row.get("row_index")))
                except Exception:
                    pass
        row_refs = sorted(set(row_refs))
        assigned_rows.update(row_refs)
        if not row_refs and not matched_clusters:
            continue

        evidence_preview = _top_rows(
            [row_by_idx[i] for i in row_refs if i in row_by_idx],
            evidence_cap,
        )
        cases.append({
            "cluster_id": spec["case_id"],
            "case_id": spec["case_id"],
            "incident_name": spec["incident_name"],
            "case_role": spec["case_role"],
            "verdict": spec["verdict"],
            "final_verdict": spec["verdict"],
            "severity": spec["severity"],
            "confidence": spec["confidence"],
            "confidence_calibration": "uncalibrated",
            "lead_description": spec["lead_description"],
            "headline_subtitle": spec["headline_subtitle"],
            "row_refs": row_refs,
            "row_count": len(row_refs),
            "supporting_cluster_ids": matched_clusters,
            "evidence_preview": evidence_preview,
            "tier1_prefill": {
                "incident_name": spec["incident_name"],
                "headline_subtitle": spec["headline_subtitle"],
                "short_narrative": spec["lead_description"],
                "what_happened": spec["lead_description"],
                "confidence_meter": {"total": int(spec["confidence"] * 100), "segments": {}},
                "top_actions": [],
                "mitre_techniques": [],
                "verdict_reasoning": "",
                "mitre_evidence_map": {},
            },
        })

    # ── Unclassified telemetry bucket ─────────────────────────────────────────
    noise_by_source: dict[str, int] = defaultdict(int)
    for row in telemetry_rows:
        try:
            idx = int(row.get("row_index"))
        except Exception:
            continue
        if idx in assigned_rows:
            continue
        noise_by_source[str(row.get("_source") or row.get("source_file") or "unknown")] += 1

    remaining_clusters = [
        str(c.get("cluster_id") or "")
        for c in clusters
        if str(c.get("cluster_id") or "") not in assigned_clusters
    ]
    remaining_rows = sum(noise_by_source.values())
    if remaining_rows:
        cases.append({
            "cluster_id": "case-unclassified-telemetry",
            "case_id": "case-unclassified-telemetry",
            "incident_name": "UNCLASSIFIED TELEMETRY",
            "case_role": "unclassified",
            "verdict": "NO_VALIDATED_BREACH",
            "final_verdict": "NO_VALIDATED_BREACH",
            "severity": "info",
            "confidence": 0.7,
            "confidence_calibration": "uncalibrated",
            "lead_description": "Remaining telemetry is unclassified — not confirmed benign",
            "headline_subtitle": "Stored as searchable supporting evidence. Not confirmed breach or benign. Requires further investigation.",
            "row_refs": [],
            "row_count": remaining_rows,
            "supporting_cluster_ids": remaining_clusters[:50],
            "source_counts": dict(noise_by_source),
            "evidence_preview": [],
        })

    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }
    return sorted(cases, key=lambda c: (severity_order.get(str(c.get("severity")), 9), -float(c.get("confidence") or 0)))
