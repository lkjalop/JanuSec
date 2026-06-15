"""Score whether a cluster's rows form one coherent attack story."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from .mitre_phase_mapping import technique_to_phase, KILLCHAIN_PHASE_ORDER

COHERENCE_WEIGHTS: dict[str, float] = {
    'shared_entities': 0.25,
    'temporal_contiguity': 0.20,
    'kill_chain_coherence': 0.25,
    'mitre_technique_affinity': 0.15,
    'source_corroboration': 0.15,
}

COHERENCE_THRESHOLD = 0.75


@dataclass
class CoherenceResult:
    score: float
    component_scores: Dict[str, float]
    keep_as_single_incident: bool


def compute_story_coherence(rows: List[dict], entities: Dict[str, List[str]]) -> CoherenceResult:
    component: dict[str, float] = {}
    component['shared_entities'] = _score_shared_entities(rows, entities)
    component['temporal_contiguity'] = _score_temporal_contiguity(rows)
    component['kill_chain_coherence'] = _score_kill_chain_coherence(rows)
    component['mitre_technique_affinity'] = _score_mitre_affinity(rows)
    component['source_corroboration'] = _score_source_corroboration(rows)

    total = sum(component[k] * COHERENCE_WEIGHTS[k] for k in COHERENCE_WEIGHTS)
    return CoherenceResult(
        score=round(total, 4),
        component_scores=component,
        keep_as_single_incident=(total >= COHERENCE_THRESHOLD),
    )


def _score_shared_entities(rows: List[dict], entities: Dict[str, List[str]]) -> float:
    if not rows:
        return 0.0
    all_values: set[str] = set()
    for vals in entities.values():
        all_values.update(str(v) for v in vals if v)
    if not all_values:
        return 0.5
    matching = sum(
        1 for r in rows
        if len(set(_extract_row_entities(r)) & all_values) >= 2
    )
    return matching / len(rows)


def _score_temporal_contiguity(rows: List[dict]) -> float:
    if not rows:
        return 0.0
    # NB: explicit None checks, not `a or b` — a legitimate epoch of 0 is falsy and
    # an `or` chain would drop it, collapsing the span and mis-scoring as 1.0.
    def _first_ts(r: dict):
        for _k in ('timestamp_utc', 'timestamp_epoch', '_ts_epoch', 'timestamp'):
            _v = r.get(_k)
            if _v is not None:
                return _v
        return None
    times = [_parse_time(_first_ts(r)) for r in rows]
    times = [t for t in times if t is not None]
    if len(times) < 2:
        return 1.0
    span_days = (max(times) - min(times)) / 86400
    if span_days < 1:
        return 1.0
    if span_days <= 30:
        return 0.9
    if span_days <= 90:
        return 0.6
    return 0.2


def _score_kill_chain_coherence(rows: List[dict]) -> float:
    phases = []
    for r in rows:
        techs = r.get('mitre') or ([r['mitre_technique']] if r.get('mitre_technique') else [])
        for t in techs:
            p = technique_to_phase(str(t))
            if p != 'unknown':
                phases.append(p)
    if not phases:
        return 0.3
    indices = [KILLCHAIN_PHASE_ORDER.index(p) for p in phases if p in KILLCHAIN_PHASE_ORDER]
    if len(indices) < 2:
        return 0.5
    inversions = sum(1 for i in range(1, len(indices)) if indices[i] < indices[i - 1] - 1)
    return max(0.0, 1.0 - (inversions / len(indices)) * 2)


def _score_mitre_affinity(rows: List[dict]) -> float:
    techniques = []
    for r in rows:
        techs = r.get('mitre') or ([r['mitre_technique']] if r.get('mitre_technique') else [])
        techniques.extend(str(t) for t in techs if t)
    if not techniques:
        return 0.5
    top_level = {t.split('.')[0] for t in techniques}
    n = len(top_level)
    if n == 1:
        return 1.0
    if n <= 3:
        return 0.8
    if n <= 6:
        return 0.5
    return 0.3


def _score_source_corroboration(rows: List[dict]) -> float:
    sources = {r.get('_source_type') or r.get('source_sheet') or r.get('source_file') or r.get('source_type')
               for r in rows}
    sources.discard(None)
    n = len(sources)
    if n >= 3:
        return 1.0
    if n == 2:
        return 0.7
    return 0.4


def _extract_row_entities(row: dict) -> List[str]:
    ents = []
    for field in ('user_principal_name', 'hostname', 'src_ip', 'dst_ip',
                  'username', 'dns_query', 'target_app_or_resource'):
        v = row.get(field)
        if v:
            ents.append(str(v))
    for acc in (row.get('accounts') or []):
        if acc:
            ents.append(str(acc))
    return ents


def _parse_time(val):
    if val is None:
        return None
    if isinstance(val, (int, float)):
        return float(val)
    if isinstance(val, datetime):
        return val.timestamp()
    if isinstance(val, timedelta):
        return val.total_seconds()
    try:
        return datetime.fromisoformat(str(val).replace('Z', '+00:00')).timestamp()
    except (ValueError, TypeError):
        return None
