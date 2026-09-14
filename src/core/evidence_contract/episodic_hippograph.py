"""Shadow associative retrieval over immutable security episodes.

This is HippoRAG/PPR-inspired memory, not an evidence or causal graph. Results
are candidates with explicit bases and must pass Evidence Pack verification.
"""

from __future__ import annotations

import datetime as dt
import math
from collections import Counter, defaultdict
from typing import Any


def _time(value: Any) -> dt.datetime | None:
    if not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)
    except Exception:
        return None


def build_episode_shadow_graph(
    episodes: list[dict[str, Any]], *, max_gap_days: float = 30.0,
) -> dict[str, Any]:
    nodes = {str(item.get("episode_id")): dict(item) for item in episodes if item.get("episode_id")}
    entity_frequency = Counter(entity for item in nodes.values() for entity in item.get("entity_ids") or [])
    hub_threshold = max(3, math.ceil(len(nodes) * 0.5))
    adjacency: dict[str, list[dict[str, Any]]] = defaultdict(list)
    excluded: list[dict[str, Any]] = []
    ids = sorted(nodes)
    for offset, source_id in enumerate(ids):
        source = nodes[source_id]
        for target_id in ids[offset + 1:]:
            target = nodes[target_id]
            if source.get("case_id") != target.get("case_id"):
                excluded.append({"source": source_id, "target": target_id, "reason": "cross_case_association_disabled"})
                continue
            shared_entities = sorted(
                set(source.get("entity_ids") or []) & set(target.get("entity_ids") or [])
                - {entity for entity, count in entity_frequency.items() if count > hub_threshold}
            )
            shared_phases = sorted(set(source.get("phase_ids") or []) & set(target.get("phase_ids") or []))
            shared_sources = sorted(set(source.get("source_domains") or []) & set(target.get("source_domains") or []))
            start, end = _time(source.get("interval_end")), _time(target.get("interval_start"))
            gap_days = abs((end - start).total_seconds()) / 86400.0 if start and end else None
            bases = sum(bool(value) for value in (shared_entities, shared_phases, shared_sources))
            if not shared_entities or bases < 2:
                excluded.append({"source": source_id, "target": target_id, "reason": "insufficient_independent_association_basis"})
                continue
            if gap_days is not None and gap_days > max_gap_days:
                excluded.append({"source": source_id, "target": target_id, "reason": "outside_temporal_association_window"})
                continue
            weight = min(1.0, 0.45 + 0.15 * len(shared_entities) + 0.1 * len(shared_phases) + 0.05 * len(shared_sources))
            if gap_days is not None:
                weight *= math.exp(-gap_days / max(1.0, max_gap_days))
            edge = {
                "source": source_id, "target": target_id, "weight": round(weight, 6),
                "basis": {"shared_entities": shared_entities, "shared_phases": shared_phases, "shared_sources": shared_sources, "gap_days": gap_days},
                "epistemic_type": "shadow_association",
            }
            adjacency[source_id].append(edge)
            adjacency[target_id].append({**edge, "source": target_id, "target": source_id})
    return {"nodes": nodes, "adjacency": dict(adjacency), "excluded": excluded, "status": "shadow_not_evidence"}


def retrieve_episode_candidates(
    graph: dict[str, Any], seed_episode_ids: list[str], *, top_k: int = 20,
    iterations: int = 12, restart_probability: float = 0.20,
) -> list[dict[str, Any]]:
    nodes, adjacency = graph.get("nodes") or {}, graph.get("adjacency") or {}
    seeds = [value for value in seed_episode_ids if value in nodes]
    if not seeds:
        return []
    restart = {node_id: 1.0 / len(seeds) for node_id in seeds}
    scores = dict(restart)
    for _ in range(max(1, iterations)):
        updated = {node_id: restart_probability * value for node_id, value in restart.items()}
        for source, score in scores.items():
            outgoing = adjacency.get(source) or []
            total = sum(float(edge.get("weight") or 0) for edge in outgoing)
            if total <= 0:
                continue
            for edge in outgoing:
                target = str(edge.get("target"))
                updated[target] = updated.get(target, 0.0) + (1 - restart_probability) * score * float(edge.get("weight") or 0) / total
        scores = updated
    return [
        {
            "episode_id": episode_id, "score": round(score, 8),
            "case_id": nodes[episode_id].get("case_id"),
            "reason": "ppr_shadow_candidate_requires_local_corroboration",
        }
        for episode_id, score in sorted(scores.items(), key=lambda item: (-item[1], item[0]))
        if episode_id not in seeds
    ][:top_k]


__all__ = ["build_episode_shadow_graph", "retrieve_episode_candidates"]
