from __future__ import annotations

from collections import Counter
from typing import Any, Iterable


CLUSTER_KEYS = (
    "clusters",
    "raw_correlation_clusters",
    "correlation_clusters",
    "analysis_clusters",
)

ROW_KEYS = (
    "normalized_rows",
    "evidence_rows",
    "rows",
    "flagged_events",
)


def get_assessment_clusters(assessment: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Return clusters from any assessment shape used by ingestion/reporting."""
    if not isinstance(assessment, dict):
        return []
    for key in CLUSTER_KEYS:
        clusters = assessment.get(key)
        if isinstance(clusters, list) and clusters:
            return [c for c in clusters if isinstance(c, dict)]
    return []


def get_assessment_rows(assessment: dict[str, Any] | None, limit: int | None = None) -> list[dict[str, Any]]:
    if not isinstance(assessment, dict):
        return []
    rows: list[dict[str, Any]] = []
    for key in ROW_KEYS:
        value = assessment.get(key)
        if isinstance(value, list) and value:
            rows = [r for r in value if isinstance(r, dict)]
            break
    if not rows:
        for cluster in get_assessment_clusters(assessment):
            for row in cluster.get("evidence_preview") or []:
                if isinstance(row, dict):
                    rows.append(row)
                    if limit is not None and len(rows) >= limit:
                        return rows
    return rows[:limit] if limit is not None else rows


def get_cluster_rows(
    assessment: dict[str, Any] | None,
    cluster: dict[str, Any] | None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    if not isinstance(cluster, dict):
        return []
    preview = [r for r in (cluster.get("evidence_preview") or []) if isinstance(r, dict)]
    if preview:
        return preview[:limit] if limit is not None else preview

    refs = set()
    for ref in cluster.get("row_refs") or []:
        try:
            refs.add(int(ref))
        except Exception:
            refs.add(str(ref))
    if not refs:
        return []

    matched: list[dict[str, Any]] = []
    for row in get_assessment_rows(assessment):
        candidates = (
            row.get("row_index"),
            row.get("_row_index"),
            row.get("row_id"),
            row.get("event_id"),
        )
        if any(c in refs or str(c) in refs for c in candidates):
            matched.append(row)
            if limit is not None and len(matched) >= limit:
                break
    return matched


def iter_cluster_factors(cluster: dict[str, Any] | None) -> Iterable[str]:
    if not isinstance(cluster, dict):
        return
    factor_sources = (
        cluster.get("factor_tags") or [],
        cluster.get("_chrono_factors") or [],
        cluster.get("factors") or [],
        cluster.get("compliance_violations") or [],
    )
    seen: set[str] = set()
    for source in factor_sources:
        if not isinstance(source, list):
            continue
        for item in source:
            if isinstance(item, dict):
                value = item.get("name") or item.get("factor") or item.get("id") or item.get("label")
            else:
                value = item
            text = str(value or "").strip()
            if text and text not in seen:
                seen.add(text)
                yield text


def factor_counts(clusters: list[dict[str, Any]] | None) -> Counter[str]:
    counts: Counter[str] = Counter()
    for cluster in clusters or []:
        counts.update(iter_cluster_factors(cluster))
    return counts


def verdict_counts(clusters: list[dict[str, Any]] | None) -> Counter[str]:
    counts: Counter[str] = Counter()
    for cluster in clusters or []:
        verdict = str(cluster.get("final_verdict") or cluster.get("verdict") or "UNKNOWN").upper()
        counts[verdict] += 1
    return counts


def validated_breach_clusters(clusters: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [
        c for c in (clusters or [])
        if "VALIDATED_BREACH" in str(c.get("verdict") or c.get("final_verdict") or "").upper()
    ]
