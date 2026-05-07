"""Main orchestrator: split assessment clusters into coherent Incident objects."""
from __future__ import annotations
import hashlib
import logging
from typing import Dict, List, Optional

from .entity_graph_segmentation import segment_entity_graph
from .incident_naming import generate_incident_name
from .incident_schema import CoherenceWarning, Incident
from .kill_chain_phase_detector import detect_kill_chain_phases, phase_span
from .mitre_phase_mapping import technique_to_phase
from .parallel_incident_detector import detect_parallel_incidents
from .story_coherence import COHERENCE_THRESHOLD, compute_story_coherence

logger = logging.getLogger(__name__)

_MIN_ROWS_FOR_SPLIT = 4


def extract_incidents(clusters: List[dict], all_rows: Optional[List[dict]] = None) -> List[Incident]:
    """Convert assessment correlation clusters into structured Incident objects.

    Args:
        clusters: List of cluster dicts from _build_correlation_clusters / get_assessment.
        all_rows: Optional flat list of all raw rows (used for row_refs resolution).

    Returns:
        List of Incident objects, one or more per input cluster.
    """
    incidents: list[Incident] = []
    row_index: dict[int, dict] = {}
    for i, row in enumerate(all_rows or []):
        row_index[i] = row
        try:
            row_index[int(float(row.get('row_index')))] = row
        except (AttributeError, TypeError, ValueError):
            pass
    idx = 0

    for cluster in clusters:
        idx += 1
        try:
            new_incidents = _process_cluster(cluster, row_index, idx)
            incidents.extend(new_incidents)
            idx += len(new_incidents) - 1
        except Exception as exc:
            logger.warning('incident_splitter: cluster %s failed: %s', cluster.get('cluster_id'), exc)

    return incidents


def _process_cluster(cluster: dict, row_index: dict, base_idx: int) -> List[Incident]:
    cid = cluster.get('cluster_id') or f'c{base_idx}'
    rows = _resolve_rows(cluster, row_index)
    entities = cluster.get('entities') or {}
    severity = cluster.get('severity') or 'medium'
    confidence = float(cluster.get('confidence') or 0.5)
    prefill = cluster.get('prefill') or {}
    what_happened = (prefill.get('what_happened') or '').strip()

    if not rows:
        return [_cluster_to_incident(cluster, rows, cid, base_idx, what_happened)]

    coherence = compute_story_coherence(rows, entities)

    # Attempt graph-based split for large incoherent clusters
    if not coherence.keep_as_single_incident and len(rows) >= _MIN_ROWS_FOR_SPLIT:
        segments = segment_entity_graph(rows)
        if len(segments) > 1:
            logger.info('incident_splitter: cluster %s split into %d segments', cid, len(segments))
            return _segments_to_incidents(cluster, segments, cid, base_idx, entities, severity, confidence)

    # Check for parallel chains even in coherent clusters
    is_parallel, parallel_rationale = detect_parallel_incidents(rows)
    if is_parallel and len(rows) >= _MIN_ROWS_FOR_SPLIT:
        segments = segment_entity_graph(rows)
        if len(segments) > 1:
            logger.info('incident_splitter: parallel chains in %s → split into %d', cid, len(segments))
            return _segments_to_incidents(cluster, segments, cid, base_idx, entities, severity, confidence,
                                          split_rationale=parallel_rationale)

    # Single incident — determine coherence warning
    warning = _coherence_warning(coherence.score, is_parallel)
    incident = _make_incident(
        incident_id=_make_id(cid, 0),
        name=generate_incident_name(rows, entities, base_idx, severity, what_happened),
        source_cluster_ids=[cid],
        rows=rows,
        entities=entities,
        severity=severity,
        confidence=confidence,
        coherence_score=coherence.score,
        coherence_warning=warning,
    )
    return [incident]


def _segments_to_incidents(
    cluster: dict,
    segments: List[List[dict]],
    cid: str,
    base_idx: int,
    entities: Dict,
    severity: str,
    confidence: float,
    split_rationale: Optional[str] = None,
) -> List[Incident]:
    incidents = []
    for seg_idx, seg_rows in enumerate(segments):
        seg_entities = _entities_from_rows(seg_rows)
        seg_coherence = compute_story_coherence(seg_rows, seg_entities)
        inc = _make_incident(
            incident_id=_make_id(cid, seg_idx + 1),
            name=generate_incident_name(seg_rows, seg_entities, base_idx + seg_idx, severity),
            source_cluster_ids=[cid],
            rows=seg_rows,
            entities=seg_entities,
            severity=severity,
            confidence=confidence * seg_coherence.score,
            coherence_score=seg_coherence.score,
            coherence_warning=CoherenceWarning.MIXED_CORRELATIONS if not seg_coherence.keep_as_single_incident else CoherenceWarning.NONE,
            split_rationale=split_rationale or f'Segmented from {cid} (entity graph cut)',
        )
        incidents.append(inc)
    return incidents


def _make_incident(
    incident_id: str,
    name: str,
    source_cluster_ids: List[str],
    rows: List[dict],
    entities: Dict,
    severity: str,
    confidence: float,
    coherence_score: float,
    coherence_warning: CoherenceWarning,
    split_rationale: Optional[str] = None,
) -> Incident:
    techniques = list({t for row in rows for t in _row_techniques(row)})
    phases = detect_kill_chain_phases(rows)
    start_t, end_t = _time_span(rows)
    source_types = list({
        row.get('_source_type') or row.get('source_sheet') or row.get('source_file') or row.get('source_type') or 'unknown'
        for row in rows
    })
    return Incident(
        incident_id=incident_id,
        name=name,
        source_cluster_ids=source_cluster_ids,
        row_refs=[row.get('row_index', -1) for row in rows],
        entities=entities,
        mitre_techniques=techniques,
        kill_chain_phases=phases,
        start_time=start_t,
        end_time=end_t,
        severity=severity,
        confidence=round(confidence, 4),
        coherence_score=coherence_score,
        coherence_warning=coherence_warning,
        source_types=source_types,
        split_rationale=split_rationale,
    )


def _cluster_to_incident(cluster: dict, rows: List[dict], cid: str, idx: int, what_happened: str) -> Incident:
    entities = cluster.get('entities') or {}
    return _make_incident(
        incident_id=_make_id(cid, 0),
        name=generate_incident_name(rows, entities, idx, cluster.get('severity') or 'medium', what_happened),
        source_cluster_ids=[cid],
        rows=rows,
        entities=entities,
        severity=cluster.get('severity') or 'medium',
        confidence=float(cluster.get('confidence') or 0.5),
        coherence_score=0.0,
        coherence_warning=CoherenceWarning.NONE,
    )


def _resolve_rows(cluster: dict, row_index: dict) -> List[dict]:
    row_refs = cluster.get('row_refs') or []
    if row_refs and row_index:
        resolved = [row_index[r] for r in row_refs if r in row_index]
        if resolved:
            return resolved
    return cluster.get('rows') or []


def _entities_from_rows(rows: List[dict]) -> Dict[str, List[str]]:
    fields = ('user_principal_name', 'username', 'hostname', 'src_ip', 'dst_ip',
              'dns_query', 'target_app_or_resource', 'account_id')
    result: dict[str, list[str]] = {}
    for field in fields:
        vals = list({str(r[field]) for r in rows if r.get(field)})
        if vals:
            result[field] = vals
    return result


def _row_techniques(row: dict) -> List[str]:
    techs = row.get('mitre') or []
    if not techs and row.get('mitre_technique'):
        techs = [row['mitre_technique']]
    return [str(t) for t in techs if t]


def _time_span(rows: List[dict]) -> tuple[str, str]:
    times = []
    for r in rows:
        v = r.get('timestamp_utc') or r.get('timestamp_epoch') or r.get('_ts_epoch') or r.get('timestamp')
        if v:
            times.append(str(v))
    if not times:
        return ('', '')
    times.sort()
    return (times[0], times[-1])


def _coherence_warning(score: float, is_parallel: bool) -> CoherenceWarning:
    if is_parallel:
        return CoherenceWarning.MIXED_CORRELATIONS
    if score < 0.4:
        return CoherenceWarning.TEMPORAL_ANOMALY
    if score < COHERENCE_THRESHOLD:
        return CoherenceWarning.SINGLE_CHAIN_INFERRED
    return CoherenceWarning.NONE


def _make_id(cluster_id: str, seg_idx: int) -> str:
    raw = f'{cluster_id}:{seg_idx}'
    h = hashlib.sha1(raw.encode()).hexdigest()[:8]
    return f'INC-{h}'
