"""Deterministic threat-case collapse for async assessment ingest.

Raw correlation clusters are useful evidence, but the breach UI needs a small
set of analyst-facing threat cases: primary breach, authorised test activity,
benign user activity, approved travel, and residual noise.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any


# Generic threat-case templates — matched against cluster text at runtime.
# Terms are real TTPs/dispositions, not scenario-specific names or IPs.
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
) -> list[dict]:
    """Collapse raw clusters into a small analyst-facing threat-case set."""
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
        cluster_rows[cid] = rows
        cluster_texts[cid] = " ".join(
            [
                str(cluster.get("lead_description") or ""),
                str(cluster.get("reason_summary") or ""),
                " ".join(_row_text(r) for r in rows[:250]),
            ]
        ).lower()

    assigned_clusters: set[str] = set()
    assigned_rows: set[int] = set()
    cases: list[dict[str, Any]] = []

    for spec in _CASE_DEFS:
        terms = [t.lower() for t in spec["terms"]]
        matched_clusters = [
            cid for cid, text in cluster_texts.items()
            if any(term in text for term in terms)
        ]
        matched_rows = [
            row for row in evidence_rows
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

    noise_by_source: dict[str, int] = defaultdict(int)
    for row in evidence_rows:
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
            "cluster_id": "case-normal-noise",
            "case_id": "case-normal-noise",
            "incident_name": "NORMAL BACKGROUND NOISE",
            "case_role": "noise",
            "verdict": "NO_VALIDATED_BREACH",
            "final_verdict": "NO_VALIDATED_BREACH",
            "severity": "info",
            "confidence": 0.7,
            "lead_description": "Remaining telemetry did not form a validated threat case",
            "headline_subtitle": "Stored as searchable supporting evidence, not an analyst work queue.",
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
