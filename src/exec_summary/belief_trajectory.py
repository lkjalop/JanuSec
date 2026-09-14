"""Belief trajectory extraction from the bitemporal dispatch trace store.

Queries the InMemoryDecisionTraceStore for each cluster's classification
history and returns a structured BeliefTrajectory with ordered transitions.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from .schemas import BeliefTrajectory, BeliefTransition

logger = logging.getLogger(__name__)

# All persona keys used in dispatch — we scan across all to build
# the composite trajectory for a cluster.
_PERSONA_KEYS = ('soc_analyst', 'ciso', 'executive', 'threat_hunter',
                 'forensics', 'compliance', 'mssp')


def _get_trace_store() -> Any:
    """Lazy-import the global trace store from the assessment worker."""
    try:
        from src.core.ingest.assessment_worker import _get_trace_store as _gts
        return _gts()
    except Exception:
        return None


def extract_belief_trajectory(
    cluster_id: str,
    tenant_id: str = 'default',
    assessment: Optional[dict] = None,
) -> BeliefTrajectory:
    """Build a BeliefTrajectory for a cluster from the bitemporal trace store.

    Falls back to inferring a single-point trajectory from the assessment's
    current cluster state when the trace store has no history.
    """
    store = _get_trace_store()
    transitions: list[BeliefTransition] = []

    if store is not None:
        # Collect all decisions across all personas for this cluster
        all_decisions = []
        for persona in _PERSONA_KEYS:
            try:
                active = store.find_active(
                    cluster_id=cluster_id,
                    persona=persona,
                    tenant_id=tenant_id,
                )
                all_decisions.extend(active)
            except Exception:
                continue

        # Sort by transaction_time to get chronological ordering
        all_decisions.sort(key=lambda d: d.transaction_time)

        # Build transitions from consecutive decisions
        prev_verdict: Optional[str] = None
        prev_confidence: Optional[float] = None
        for dec in all_decisions:
            new_verdict = dec.verdict or 'UNCERTAIN'
            new_confidence = dec.confidence
            if new_verdict != prev_verdict or new_confidence != prev_confidence:
                transitions.append(BeliefTransition(
                    transaction_time=dec.transaction_time,
                    prior_classification=prev_verdict,
                    new_classification=new_verdict,
                    prior_confidence=prev_confidence,
                    new_confidence=new_confidence,
                    triggering_evidence_ids=dec.evidence_row_indices or [],
                    triggering_reason=f'{dec.persona} dispatch',
                ))
            prev_verdict = new_verdict
            prev_confidence = new_confidence

    # Infer current state from assessment cluster if no trace history
    current_class = 'UNCERTAIN'
    current_conf: Optional[float] = None
    data_available = len(transitions) > 0

    if assessment:
        cluster = _find_cluster(assessment, cluster_id)
        if cluster:
            current_class = str(
                cluster.get('verdict') or cluster.get('final_verdict') or 'UNCERTAIN'
            ).upper()
            current_conf = cluster.get('confidence')
            if not transitions:
                # Synthesize a single-point "trajectory" from current state
                transitions.append(BeliefTransition(
                    transaction_time='',
                    prior_classification=None,
                    new_classification=current_class,
                    prior_confidence=None,
                    new_confidence=current_conf,
                    triggering_evidence_ids=cluster.get('row_refs') or [],
                    triggering_reason='current assessment state (no trace history)',
                ))

    if transitions:
        current_class = transitions[-1].new_classification
        current_conf = transitions[-1].new_confidence

    return BeliefTrajectory(
        cluster_id=cluster_id,
        transitions=transitions,
        current_classification=current_class,
        current_confidence=current_conf,
        data_available=data_available,
    )


def format_trajectory_oneliner(trajectory: BeliefTrajectory) -> str:
    """Produce a human-readable one-liner for the belief evolution."""
    if not trajectory.transitions:
        return f'{trajectory.current_classification} (no history)'
    if len(trajectory.transitions) == 1:
        t = trajectory.transitions[0]
        conf = f' ({t.new_confidence:.0%})' if t.new_confidence is not None else ''
        return f'{t.new_classification}{conf}'
    parts = []
    for t in trajectory.transitions:
        conf = f' ({t.new_confidence:.0%})' if t.new_confidence is not None else ''
        parts.append(f'{t.new_classification}{conf}')
    return ' → '.join(parts)


def _find_cluster(assessment: dict, cluster_id: str) -> Optional[dict]:
    """Locate a cluster by ID in the assessment."""
    for pool_key in ('threat_cases', 'correlation_clusters'):
        for c in assessment.get(pool_key) or []:
            if str(c.get('cluster_id', '')) == str(cluster_id):
                return c
    return None
