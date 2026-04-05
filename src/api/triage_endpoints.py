from __future__ import annotations
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from src.core.correlation.triage_dedup import bucket_by_hash, mini_batch_k_medoids
from src.api.session_store import get_session_store
from src.reporting.tiered_triage import TriageConfig, triage_alerts
from src.reporting.analyst_gate import get_analyst_gate, GateState
from database_adapter import store_dedup_run, store_dedup_cluster, get_dedup_runs, get_dedup_clusters
import time, uuid, json, logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix='/api/v1/triage', tags=['triage'])


@router.post('/dedup')
async def dedup_triage(request: Request, session_ids: List[str] | None = None, rows: List[Dict[str, Any]] | None = None, k: int = 3):
    """Perform dedup clustering. Provide `session_ids` to load persisted sessions or pass `rows` directly."""
    if session_ids is None and rows is None:
        raise HTTPException(status_code=400, detail='session_ids or rows required')
    data_rows = []
    if session_ids:
        store = get_session_store()
        for sid in session_ids:
            try:
                s = store.load(sid)
                # `s` may be a dict with metadata and rows; attempt to extract `events` or `rows`
                if isinstance(s, dict):
                    extracted = s.get('events') or s.get('rows') or s.get('session') or s
                else:
                    extracted = s
                # if extracted is a list, extend; else append as single row
                if isinstance(extracted, list):
                    data_rows.extend(extracted)
                elif isinstance(extracted, dict):
                    data_rows.append(extracted)
                else:
                    try:
                        data_rows.append(dict(extracted))
                    except Exception:
                        data_rows.append({'raw': str(extracted)})
            except Exception as exc:
                # best-effort: continue
                continue
    if rows:
        data_rows.extend(rows)
    if not data_rows:
        raise HTTPException(status_code=404, detail='no rows found for given session_ids')
    # quick bucket then cluster each bucket
    buckets = bucket_by_hash(data_rows, ['user', 'host', 'sha256'])
    clusters = []
    for bid, bucket_rows in buckets.items():
        medoids, assignments = mini_batch_k_medoids(bucket_rows, k=k, random_state=42)
        clusters.append({'bucket': bid, 'medoids': medoids, 'assignments': assignments, 'rows_count': len(bucket_rows)})
    return {'clusters': clusters, 'total_rows': len(data_rows)}


@router.post('/dedup/persist')
async def dedup_persist(request: Request, rows: List[Dict[str, Any]] | None = None, k: int = 3, run_id: str | None = None):
    """Run dedup clustering and persist the run and clusters to DB."""
    if rows is None:
        raise HTTPException(status_code=400, detail='rows required')
    data_rows = rows
    buckets = bucket_by_hash(data_rows, ['user', 'host', 'sha256'])
    clusters = []
    for bid, bucket_rows in buckets.items():
        medoids, assignments = mini_batch_k_medoids(bucket_rows, k=k, random_state=42)
        # build members lists per medoid
        members_per = {i: [] for i in range(len(medoids))}
        for idx, assign in enumerate(assignments):
            members_per[assign].append(bucket_rows[idx])
        for mi, m in enumerate(medoids):
            clusters.append({'bucket': bid, 'medoid': m, 'members': members_per.get(mi, []), 'rows_count': len(members_per.get(mi, []))})

    rid = run_id or f"dedup-{int(time.time())}-{uuid.uuid4().hex[:8]}"
    params = {'k': k, 'method': 'mini_batch_k_medoids'}
    summary = {'total_rows': len(data_rows), 'buckets': len(buckets), 'clusters': len(clusters)}
    await store_dedup_run(rid, params, summary, tenant_id='default')
    for c in clusters:
        await store_dedup_cluster(rid, c.get('bucket', 0), c.get('medoid') or {}, c.get('members') or [], c.get('rows_count'))

    return {'run_id': rid, 'summary': summary}


@router.get('/runs')
async def list_dedup_runs(limit: int = 50, offset: int = 0):
    rows = await get_dedup_runs(limit=limit, offset=offset)
    return {'runs': rows}


@router.get('/runs/{run_id}')
async def get_dedup_run(run_id: str):
    runs = await get_dedup_runs(limit=1, offset=0)
    # find run
    run = None
    for r in runs:
        if r['id'] == run_id:
            run = r
            break
    clusters = await get_dedup_clusters(run_id)
    # Normalize cluster payload: ensure medoid_sample exists for quick UI preview
    for c in clusters:
        med = c.get('medoid') or {}
        members = c.get('members') or []
        # medoid_sample: prefer medoid (if representative row), else first member
        if not med:
            c['medoid_sample'] = members[0] if members else {}
        else:
            # if med lacks obvious fields, but members exist, prefer med as-is but include an explicit sample
            c['medoid_sample'] = med
        # Attach member_count for convenience
        c['member_count'] = len(members)
    return {'run': run, 'clusters': clusters}


# ── Pydantic models for batch triage + analyst gate ────────────────────

class TriageBatchRequest(BaseModel):
    alerts: List[Dict[str, Any]]
    config: Optional[Dict[str, Any]] = None


class GateApproveRequest(BaseModel):
    alert_id: str
    analyst: str
    notes: str = ''
    tags: List[str] = Field(default_factory=list)
    confidence_override: Optional[float] = None
    factors_added: List[str] = Field(default_factory=list)
    factors_removed: List[str] = Field(default_factory=list)


class GateRejectRequest(BaseModel):
    alert_id: str
    analyst: str
    notes: str = ''
    tags: List[str] = Field(default_factory=list)


class GateDeferRequest(BaseModel):
    alert_id: str
    analyst: str
    notes: str = ''
    context_requests: List[str] = Field(default_factory=list)


# ── Batch triage (score → tier → cluster → persona-route → gate) ──────

@router.post('/batch')
async def triage_batch(body: TriageBatchRequest):
    """Score, tier, cluster and route a batch of alerts.

    Returns per-tier buckets, persona queues, clusters, gate list, and stats.
    """
    if not body.alerts:
        raise HTTPException(status_code=400, detail='empty_alerts')

    cfg = TriageConfig()
    if body.config:
        for k, v in body.config.items():
            if hasattr(cfg, k):
                setattr(cfg, k, v)

    result = triage_alerts(body.alerts, config=cfg)

    # Auto-submit gated alerts to the analyst gate
    gate = get_analyst_gate()
    gate_entries = []
    for alert_id in result.human_gate_required:
        score = 0.0
        tier = 'P2'
        for t, scored_list in result.tiers.items():
            for sa in scored_list:
                if sa.alert_id == alert_id:
                    score = sa.priority_score
                    tier = sa.tier
                    break
        entry = gate.submit(alert_id=alert_id, tier=tier, priority_score=score)
        gate_entries.append({
            'alert_id': entry.alert_id,
            'state': entry.state.value,
            'tier': entry.tier,
            'priority_score': entry.priority_score,
        })

    return {
        'tiers': {
            t: [
                {
                    'alert_id': sa.alert_id,
                    'priority_score': sa.priority_score,
                    'tier': sa.tier,
                    'severity': sa.severity,
                    'verdict': sa.verdict,
                    'confidence': sa.confidence,
                    'factor_names': sa.factor_names[:8],
                    'affected_entities': sa.affected_entities[:5],
                    'mitre_tactics': sa.mitre_tactics[:5],
                    'score_breakdown': sa.score_breakdown,
                }
                for sa in scored
            ]
            for t, scored in result.tiers.items()
        },
        'persona_queues': result.persona_queues,
        'clusters': [
            {
                'cluster_id': c.cluster_id,
                'alert_count': len(c.alerts),
                'common_factors': c.common_factors,
                'common_mitre': c.common_mitre,
                'representative_alert_id': c.representative_alert_id,
                'aggregate_score': c.aggregate_score,
                'alert_ids': [a.alert_id for a in c.alerts],
            }
            for c in result.clusters
        ],
        'gate_entries': gate_entries,
        'stats': result.stats,
    }


# ── Gate: pending ──────────────────────────────────────────────────────

@router.get('/gate/pending')
async def gate_pending():
    """List all PENDING gate entries, sorted by priority descending."""
    gate = get_analyst_gate()
    entries = gate.pending()
    return {
        'pending': [
            {
                'alert_id': e.alert_id,
                'tier': e.tier,
                'state': e.state.value,
                'priority_score': e.priority_score,
                'submitted_ts': e.submitted_ts,
                'analyst_pool': e.analyst_pool,
            }
            for e in entries
        ],
        'count': len(entries),
    }


# ── Gate: approve ─────────────────────────────────────────────────────

@router.post('/gate/approve')
async def gate_approve(body: GateApproveRequest):
    """Analyst approves a gated alert for Tier-2 processing."""
    gate = get_analyst_gate()
    try:
        entry = gate.approve(
            alert_id=body.alert_id,
            analyst=body.analyst,
            notes=body.notes,
            tags=body.tags,
            confidence_override=body.confidence_override,
            factors_added=body.factors_added,
            factors_removed=body.factors_removed,
        )
    except KeyError:
        raise HTTPException(status_code=404, detail='gate_entry_not_found')
    return {
        'alert_id': entry.alert_id,
        'state': entry.state.value,
        'analyst': entry.analyst,
        'resolved_ts': entry.resolved_ts,
    }


# ── Gate: reject ──────────────────────────────────────────────────────

@router.post('/gate/reject')
async def gate_reject(body: GateRejectRequest):
    """Analyst marks alert as false positive / suppress."""
    gate = get_analyst_gate()
    try:
        entry = gate.reject(
            alert_id=body.alert_id,
            analyst=body.analyst,
            notes=body.notes,
            tags=body.tags,
        )
    except KeyError:
        raise HTTPException(status_code=404, detail='gate_entry_not_found')
    return {
        'alert_id': entry.alert_id,
        'state': entry.state.value,
        'analyst': entry.analyst,
        'resolved_ts': entry.resolved_ts,
    }


# ── Gate: defer ───────────────────────────────────────────────────────

@router.post('/gate/defer')
async def gate_defer(body: GateDeferRequest):
    """Analyst requests more context; triggers on-demand fetch hints."""
    gate = get_analyst_gate()
    try:
        entry = gate.defer(
            alert_id=body.alert_id,
            analyst=body.analyst,
            notes=body.notes,
            context_requests=body.context_requests,
        )
    except KeyError:
        raise HTTPException(status_code=404, detail='gate_entry_not_found')
    return {
        'alert_id': entry.alert_id,
        'state': entry.state.value,
        'context_requests': entry.context_requests,
    }


# ── Gate: stats ───────────────────────────────────────────────────────

@router.get('/gate/stats')
async def gate_stats():
    """Return aggregate gate queue statistics."""
    gate = get_analyst_gate()
    return gate.stats()
