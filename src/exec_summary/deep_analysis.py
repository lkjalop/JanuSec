"""Deep analysis orchestrator — Tier 3 (background async job).

Architecture: three-tier quality model with increasing latency.

Tier 1 — Instant (0s):
    Deterministic backbone. Already exists in the main exec summary.
    Returned immediately from the POST endpoint.

Tier 2 — Fast (2-15s):
    Enriched pipeline (TemporalRAG + BeliefTrajectory + grader + disposition).
    Already wired into the main exec summary route.

Tier 3 — Deep (30-120s, background):
    Triggered by `deep=true` on regenerate requests.
    Runs: CrossSourceStitcher → SequenceValidator → AdversarialReasoner
    Results stream via SSE, then cached on assessment.

The caller gets Tier 1 immediately, then polls or streams for Tier 3.
This avoids blocking the UI for 2 minutes while still delivering
the highest-quality analysis when the user explicitly requests it.

Job lifecycle:
    QUEUED → RUNNING (prosecution) → RUNNING (defense) → RUNNING (synthesis) → READY | FAILED
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

# ── In-memory job store ────────────────────────────────────────────────────────
# Keyed by job_id. Entries are pruned after TTL.

_JOB_STORE: dict[str, dict] = {}
_JOB_STORE_TTL_SECONDS = int(os.getenv('DEEP_ANALYSIS_JOB_TTL', '3600'))

# SSE event queues: job_id → list of per-client asyncio.Queue
_JOB_SSE_QUEUES: dict[str, list[asyncio.Queue]] = {}

# Global deep-analysis concurrency limit — avoids queue starvation
_SEMAPHORE: Optional[asyncio.Semaphore] = None


def _get_semaphore() -> asyncio.Semaphore:
    global _SEMAPHORE
    if _SEMAPHORE is None:
        max_concurrent = int(os.getenv('DEEP_ANALYSIS_MAX_CONCURRENT', '2'))
        _SEMAPHORE = asyncio.Semaphore(max_concurrent)
    return _SEMAPHORE


# ── Job management ────────────────────────────────────────────────────────────


def create_job(assessment_id: str) -> str:
    """Create a new deep-analysis job and return its ID."""
    _prune_old_jobs()
    job_id = str(uuid.uuid4())
    _JOB_STORE[job_id] = {
        'job_id': job_id,
        'assessment_id': assessment_id,
        'status': 'queued',
        'phase': 'queued',
        'progress': 0,
        'created_at': int(time.time()),
        'updated_at': int(time.time()),
        'result': None,
        'error': None,
    }
    return job_id


def get_job(job_id: str) -> Optional[dict]:
    return _JOB_STORE.get(job_id)


def _update_job(job_id: str, **kwargs: Any) -> None:
    if job_id in _JOB_STORE:
        _JOB_STORE[job_id].update({'updated_at': int(time.time()), **kwargs})


def _prune_old_jobs() -> None:
    cutoff = int(time.time()) - _JOB_STORE_TTL_SECONDS
    stale = [jid for jid, j in _JOB_STORE.items() if j.get('created_at', 0) < cutoff]
    for jid in stale:
        _JOB_STORE.pop(jid, None)
        _JOB_SSE_QUEUES.pop(jid, None)


# ── SSE publish / subscribe ───────────────────────────────────────────────────


def subscribe_job(job_id: str) -> asyncio.Queue:
    """Create a per-client SSE queue for a job. Returns the queue."""
    q: asyncio.Queue = asyncio.Queue()
    _JOB_SSE_QUEUES.setdefault(job_id, []).append(q)
    return q


def _publish_event(job_id: str, event_type: str, payload: dict) -> None:
    """Publish an event to all clients subscribed to this job."""
    msg = json.dumps({'type': event_type, **payload})
    for q in _JOB_SSE_QUEUES.get(job_id, []):
        try:
            q.put_nowait(msg)
        except asyncio.QueueFull:
            pass


def _progress_callback(job_id: str) -> Callable[[str, int], None]:
    """Return a progress callback that updates job state and publishes SSE events."""
    def _cb(phase: str, pct: int) -> None:
        _update_job(job_id, phase=phase, progress=pct, status='running')
        _publish_event(job_id, 'progress', {'phase': phase, 'progress': pct})
    return _cb


# ── Deep analysis per cluster ─────────────────────────────────────────────────


def _run_deep_cluster(
    cluster: dict,
    assessment: dict,
    llm_func: Optional[Callable],
    model: str,
    progress_cb: Callable[[str, int], None],
) -> dict:
    """Synchronous deep analysis for a single cluster. Called from thread."""
    from .cross_source_stitcher import stitch_cluster_evidence
    from .sequence_validator import SequenceValidator
    from .adversarial_reasoner import AdversarialReasoner
    from .verdict_reasoning import derive_verdict_reasoning

    cid = str(cluster.get('cluster_id', ''))

    # Get cluster rows
    row_refs = cluster.get('row_refs') or []
    all_rows = (
        assessment.get('normalized_rows')
        or assessment.get('evidence_rows')
        or assessment.get('rows')
        or []
    )
    row_map = {r.get('row_index', i): r for i, r in enumerate(all_rows)}
    rows = [row_map[ref] for ref in row_refs if ref in row_map]

    progress_cb(f'deep:{cid}:stitching', 10)

    # Cross-source stitching
    stitches = stitch_cluster_evidence(cluster, assessment)

    progress_cb(f'deep:{cid}:sequence', 20)

    # Sequence validation
    seq_result = SequenceValidator().validate(rows)

    progress_cb(f'deep:{cid}:grading', 25)

    # Verdict reasoning (grader + disposition)
    vr = derive_verdict_reasoning(cluster, rows, assessment)

    # Adversarial reasoning (3-pass LLM or deterministic fallback)
    adversarial_result = {}
    if llm_func:
        reasoner = AdversarialReasoner(
            llm_func=llm_func,
            model=model,
            max_tokens_per_pass=500,
            progress_callback=progress_cb,
        )
        adversarial_result = reasoner.reason(cluster, rows, stitches, seq_result, vr)
    else:
        from .adversarial_reasoner import _deterministic_synthesis
        adversarial_result = {
            'prosecution_text': '',
            'defense_text': '',
            'synthesis': _deterministic_synthesis(cluster, seq_result, vr),
            'passes_completed': 0,
            'provenance': 'deterministic',
        }

    return {
        'cluster_id': cid,
        'stitches': stitches,
        'cross_source_count': sum(1 for s in stitches if s.get('cross_source')),
        'sequence': seq_result,
        'verdict_reasoning': vr,
        'adversarial': adversarial_result,
        'synthesis': adversarial_result.get('synthesis', {}),
        'ceo_one_liner': (
            adversarial_result.get('synthesis', {}).get('ceo_one_liner', '')
        ),
    }


# ── Main async job runner ─────────────────────────────────────────────────────


async def run_deep_analysis_job(
    job_id: str,
    assessment_id: str,
    assessment: dict,
    sorted_clusters: list[dict],
    llm_func: Optional[Callable] = None,
    model: str = 'qwen3:14b',
    max_clusters: int = 5,
) -> None:
    """Run the Tier 3 deep analysis job asynchronously.

    Publishes SSE progress events and writes the final result to the job store
    and to assessment['deep_exec_summary'].
    """
    progress_cb = _progress_callback(job_id)

    async with _get_semaphore():
        try:
            _update_job(job_id, status='running', phase='starting', progress=5)
            _publish_event(job_id, 'progress', {'phase': 'starting', 'progress': 5})

            clusters_to_process = sorted_clusters[:max_clusters]
            cluster_results: list[dict] = []
            n = len(clusters_to_process)

            for i, cluster in enumerate(clusters_to_process):
                cid = str(cluster.get('cluster_id', ''))
                base_pct = 10 + int((i / max(n, 1)) * 75)

                # Per-cluster work runs in a thread to avoid blocking the event loop
                try:
                    cluster_result = await asyncio.wait_for(
                        asyncio.to_thread(
                            _run_deep_cluster,
                            cluster, assessment, llm_func, model,
                            lambda phase, pct, _b=base_pct: progress_cb(phase, _b + pct // 4),
                        ),
                        timeout=float(os.getenv('DEEP_ANALYSIS_CLUSTER_TIMEOUT_SECONDS') or os.getenv('OLLAMA_TIMEOUT_SECONDS') or os.getenv('LLM_TIMEOUT_SECONDS') or 45),
                    )
                    cluster_results.append(cluster_result)
                    _publish_event(job_id, 'cluster_complete', {
                        'cluster_id': cid,
                        'ceo_one_liner': cluster_result.get('ceo_one_liner', ''),
                        'cross_source_count': cluster_result.get('cross_source_count', 0),
                        'sequence_coherent': cluster_result.get('sequence', {}).get('sequence_coherent', False),
                        'passes_completed': cluster_result.get('adversarial', {}).get('passes_completed', 0),
                        'cluster_index': i,
                        'cluster_count': n,
                    })
                except (asyncio.TimeoutError, Exception) as exc:
                    logger.warning('deep analysis timeout/fail for cluster %s: %s', cid, exc)
                    cluster_results.append({
                        'cluster_id': cid,
                        'error': str(exc),
                    })

            # Aggregate synthesis
            progress_cb('deep:rollup', 88)
            rollup = _build_deep_rollup(cluster_results, assessment)

            result = {
                'job_id': job_id,
                'assessment_id': assessment_id,
                'cluster_results': cluster_results,
                'rollup': rollup,
                'generated_at': int(time.time()),
            }

            # Cache on assessment
            assessment['deep_exec_summary'] = result

            _update_job(job_id, status='ready', phase='complete', progress=100, result=result)
            _publish_event(job_id, 'complete', {
                'rollup': rollup,
                'cluster_count': len(cluster_results),
            })

        except Exception as exc:
            logger.error('deep analysis job %s failed: %s', job_id, exc, exc_info=True)
            _update_job(job_id, status='failed', error=str(exc)[:500])
            _publish_event(job_id, 'error', {'message': str(exc)[:200]})


def _build_deep_rollup(cluster_results: list[dict], assessment: dict) -> dict:
    """Build an assessment-level rollup from all cluster deep results."""
    total = len(cluster_results)
    successful = [r for r in cluster_results if 'error' not in r]
    cross_source_clusters = sum(1 for r in successful if r.get('cross_source_count', 0) > 0)
    coherent_sequences = sum(
        1 for r in successful
        if r.get('sequence', {}).get('sequence_coherent', False)
    )
    adversarial_completed = sum(
        1 for r in successful
        if r.get('adversarial', {}).get('passes_completed', 0) >= 3
    )

    # Collect final verdicts from synthesis
    syntheses = [r.get('synthesis', {}) for r in successful if r.get('synthesis')]
    final_verdicts = [s.get('final_verdict', '') for s in syntheses if s.get('final_verdict')]
    avg_confidence = (
        sum(s.get('confidence', 0.5) for s in syntheses) / len(syntheses)
        if syntheses else 0.0
    )

    confirmed_count = sum(
        1 for v in final_verdicts
        if v in ('CONFIRMED_BREACH', 'VALIDATED_BREACH', 'LIKELY_BREACH')
    )

    # CEO one-liners per cluster
    ceo_lines = [
        r.get('ceo_one_liner', '')
        for r in successful if r.get('ceo_one_liner')
    ]

    return {
        'cluster_count': total,
        'successful_analyses': len(successful),
        'cross_source_clusters': cross_source_clusters,
        'coherent_sequences': coherent_sequences,
        'adversarial_passes_completed': adversarial_completed,
        'confirmed_clusters': confirmed_count,
        'average_confidence': round(avg_confidence, 3),
        'final_verdicts': final_verdicts,
        'ceo_summary_lines': ceo_lines,
        'quality_note': (
            f'{adversarial_completed}/{total} clusters underwent full adversarial reasoning. '
            f'{cross_source_clusters} confirmed across multiple telemetry sources.'
        ),
    }
