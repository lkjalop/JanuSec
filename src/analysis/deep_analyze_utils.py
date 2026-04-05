"""Shared helpers for Deep Analyze canonical signal shaping."""
from __future__ import annotations

from typing import Any, Dict, Iterable, List
try:
    # Prefer unified DREAD computation with detailed breakdown
    from src.core.threat_modeling.factor_taxonomy import compute_dread_score  # type: ignore
except Exception:  # fallback when taxonomy not available
    compute_dread_score = None  # type: ignore


def build_canonical_signals(
    stage_results: Iterable[Dict[str, Any]] | None,
    ctx: Dict[str, Any] | None,
) -> Dict[str, Any]:
    """Aggregate compact canonical signals across stages and sample rows."""
    canonical: Dict[str, Any] = {}
    ctx = ctx or {}
    rows = ctx.get("rows") or []
    if rows:
        first = rows[0]
        if isinstance(first, dict):
            for key in (
                "ip",
                "ip_src",
                "ip_dst",
                "user",
                "host",
                "file_hash",
                "process",
                "file_name",
            ):
                if key in first:
                    canonical[key] = first[key]

    for stage in stage_results or []:
        name = stage.get("stage")
        result = stage.get("result") or {}
        if name == "ThreatIntel" and result.get("threat_hits") is not None:
            canonical["threat_hits"] = result.get("threat_hits")
        elif name == "GeoIP" and result.get("internal_count") is not None:
            canonical["internal_count"] = result.get("internal_count")
        elif name == "GraphTraversal" and result.get("expansions") is not None:
            canonical["graph_expansions"] = result.get("expansions")
        elif name == "LLMSummary" and result.get("llm_summary"):
            canonical["llm_summary"] = result.get("llm_summary")

    # Baseline context (best-effort)
    try:
        baseline_ctx = ctx.get("baseline_context") or {}
        if isinstance(baseline_ctx, dict):
            for k in ("baseline_frequency", "baseline_noise", "baseline_z", "baseline_samples"):
                if k in baseline_ctx:
                    canonical[k] = baseline_ctx.get(k)
        else:
            for k in ("baseline_frequency", "baseline_noise", "baseline_z", "baseline_samples"):
                if k in ctx:
                    canonical[k] = ctx.get(k)
    except Exception:
        pass

    return canonical


def map_to_mitre(canonical: Dict[str, Any]) -> List[str]:
    tags: List[str] = []
    if canonical.get("threat_hits", 0) > 0:
        tags.append("T1027")
    if canonical.get("graph_expansions", 0) > 0:
        tags.append("T1087")
    return tags


def map_to_stride(canonical: Dict[str, Any]) -> List[str]:
    tags: List[str] = []
    if canonical.get("threat_hits", 0) > 0:
        tags.append("Tampering")
    if canonical.get("internal_count", 0) > 0:
        tags.append("Repudiation")
    return tags


def map_to_controls(canonical: Dict[str, Any]) -> List[str]:
    tags: List[str] = []
    if canonical.get("threat_hits", 0) > 0:
        tags.append("AC-7")
    return tags


def map_to_dread(canonical: Dict[str, Any]) -> Dict[str, Any]:
    """Map canonical signals to a unified DREAD score.

    Uses compute_dread_score when available for consistent scoring across API/UI.
    Falls back to the prior lightweight heuristic if taxonomy is unavailable.
    """
    # If unified scorer is available, derive a minimal factor list from canonical hints
    if compute_dread_score is not None:
        try:
            factors: List[str] = []
            # Threat intel hit → treat as unusual file/hash collection signal
            if (canonical.get("threat_hits") or 0) > 0:
                factors.append("data:unusual_file_hash_collection")
            # Graph expansions → correlation/pivot sequence present
            if (canonical.get("graph_expansions") or 0) > 0:
                factors.append("corr_domain_pivot_sequence")
            # Provide canonical context to enable mapping/diversity semantics and status boosts
            res = compute_dread_score(factors, context=canonical)  # type: ignore[misc]
            # Ensure at minimum we expose a numeric score for downstream consumers
            if isinstance(res, dict) and "score" in res:
                return res
        except Exception:
            # fall through to lightweight heuristic
            pass
    # Fallback: preserve existing simple additive behavior
    score = 0
    if canonical.get("threat_hits", 0) > 0:
        score += 6
    if canonical.get("graph_expansions", 0) > 0:
        score += 2
    return {"score": score}


def map_to_pasa(canonical: Dict[str, Any]) -> Dict[str, Any]:
    return {"pasa_level": "medium" if canonical.get("threat_hits") else "low"}


def map_to_maestro(canonical: Dict[str, Any]) -> Dict[str, Any]:
    return {"maestro_tags": ["initial_access"] if canonical.get("threat_hits") else []}


def map_to_diamond(canonical: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "adversary": "unknown" if canonical.get("threat_hits") else None,
        "capability": [],
    }


__all__ = [
    "build_canonical_signals",
    "map_to_mitre",
    "map_to_stride",
    "map_to_controls",
    "map_to_dread",
    "map_to_pasa",
    "map_to_maestro",
    "map_to_diamond",
]
