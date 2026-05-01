"""Dispatch, sign-off, timeline, notes, IOC and repeat-entity endpoints.

Routes:
  POST /api/v1/assessments/{aid}/clusters/{cid}/persona-dispatch
      Regenerate one persona's dispatch payload on demand (Regenerate button).

  POST /api/v1/assessments/{aid}/clusters/{cid}/sign-off
      Analyst sign-off with notes + timeline confirmation.

  POST /api/v1/assessments/{aid}/clusters/{cid}/further-tasks
      Generate further investigation tasks grounded in uncovered evidence.

  GET  /api/v1/assessments/{aid}/clusters/{cid}/timeline
      Return rows tagged with kill-chain phase, sorted by timestamp.

  PATCH /api/v1/assessments/{aid}/clusters/{cid}/notes
      Update analyst sticky notes for a cluster.

  GET  /api/v1/assessments/{aid}/clusters/{cid}/iocs
      Return the IOC bundle for a cluster.

  GET  /api/v1/assessments/{aid}/clusters/{cid}/repeat-entities
      Scan all stored assessments for clusters sharing entities with this cluster.
"""
from __future__ import annotations

import json
import logging
import sys
import time
from typing import List

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .exec_summary_endpoints import (  # noqa: F401
    _get_assessment,
    _persist,
    _get_tenant,
    _get_llm,
    _safe_text,
    _extract_iocs,
    tag_kill_chain_phase,
    _PHASE_ORDER,
    _row_geo_asn,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix='/api/v1/assessments', tags=['breach'])


def _legacy_helper(name: str, fallback):
    mod = sys.modules.get('src.api.breach_endpoints') or sys.modules.get('api.breach_endpoints')
    value = getattr(mod, name, None) if mod is not None else None
    return value if callable(value) else fallback


# â”€â”€ Request models â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class PersonaDispatchRequest(BaseModel):
    persona: str = Field('compliance', description='Persona key to regenerate')
    regenerate: bool = False


class SignOffRequest(BaseModel):
    analyst_id: str = ''
    notes: str = ''
    timeline_confirmed: bool = False


class FurtherTasksRequest(BaseModel):
    completed_evidence_refs: List[int] = Field(default_factory=list)
    completed_task_titles: List[str] = Field(default_factory=list)
    model: str = 'qwen3:30b'


class NotesRequest(BaseModel):
    notes: str = ''
    analyst_id: str = ''


# â”€â”€ Routes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.post('/{assessment_id}/clusters/{cluster_id}/persona-dispatch')
async def regenerate_persona_dispatch(
    assessment_id: str,
    cluster_id: str,
    body: PersonaDispatchRequest,
    request: Request,
) -> JSONResponse:
    """Rebuild one persona's dispatch payload on demand.

    Used by the per-persona Regenerate button in the dispatch preview.
    Re-runs enrich_narrative + build_control_failure_register +
    build_persona_dispatch for the given persona key.
    """
    assessment = _legacy_helper('_get_assessment', _get_assessment)(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail='assessment_not_found')

    tenant_id = _get_tenant(request)
    clusters = assessment.get('correlation_clusters') or []
    cluster = next(
        (c for c in clusters if (c.get('cluster_id') or c.get('id')) == cluster_id),
        None,
    )
    if not cluster:
        raise HTTPException(status_code=404, detail='cluster_not_found')

    try:
        from src.analysis.framework_mapper import build_control_failure_register
        from src.analysis.persona_dispatch import build_persona_dispatch
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'dispatch_modules_unavailable: {exc}')

    # Enrich narrative if not already done
    narrative = cluster.get('llm_narrative') or cluster.get('tier1_prefill') or {}
    if not isinstance(narrative, dict):
        narrative = {}

    try:
        from src.llm.cluster_narrator_v2_schema import enrich_narrative
        tenant_class = None
        try:
            from src.config.tenant_data_classification import load_for_tenant
            tenant_class = load_for_tenant(tenant_id)
        except Exception:
            pass

        # Collect rows for this cluster
        all_rows = (assessment.get('normalized_rows') or
                    assessment.get('evidence_rows') or
                    assessment.get('rows') or [])
        row_lookup: dict[int, dict] = {}
        for r in all_rows:
            ri = r.get('row_index') or r.get('row_number') or r.get('id')
            if ri is not None:
                try:
                    row_lookup[int(float(ri))] = r
                except (TypeError, ValueError):
                    pass
        cl_rows = []
        for ref in (cluster.get('row_refs') or []):
            try:
                k = int(float(ref))
                if k in row_lookup:
                    cl_rows.append(row_lookup[k])
            except (TypeError, ValueError):
                pass

        narrative = enrich_narrative(
            narrative, cluster, cl_rows,
            tenant_classification=tenant_class,
        )
        if not narrative.get('mitre_techniques'):
            explicit = cluster.get('mitre_techniques') or cluster.get('mitre_tags') or []
            narrative['mitre_techniques'] = explicit
        cluster['llm_narrative'] = narrative
    except Exception as enrich_err:
        logger.warning('enrich_narrative failed in persona dispatch regen: %s', enrich_err)
        cl_rows = []

    entity_context = assessment.get('entity_context') or {}
    register = build_control_failure_register(
        narrative, evidence_rows=cl_rows, entity_context=entity_context,
        cluster=cluster,
    )

    payload = build_persona_dispatch(
        body.persona,
        narrative,
        register=register,
        evidence_rows=cl_rows,
        cluster_id=cluster_id,
    )

    # Persist updated dispatch
    if 'persona_dispatch' not in cluster:
        cluster['persona_dispatch'] = {}
    cluster['persona_dispatch'][body.persona] = payload
    _legacy_helper('_persist', _persist)(assessment_id, assessment)

    return JSONResponse({
        'assessment_id': assessment_id,
        'cluster_id': cluster_id,
        'persona': body.persona,
        'payload': payload,
    })


@router.post('/{assessment_id}/clusters/{cluster_id}/sign-off')
async def cluster_sign_off(
    assessment_id: str,
    cluster_id: str,
    body: SignOffRequest,
    request: Request,
) -> JSONResponse:
    assessment = _legacy_helper('_get_assessment', _get_assessment)(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail='assessment_not_found')

    clusters = assessment.get('correlation_clusters') or []
    cluster = next((c for c in clusters if c.get('cluster_id') == cluster_id), None)
    if not cluster:
        raise HTTPException(status_code=404, detail='cluster_not_found')

    signed_at = int(time.time())
    cluster['sign_off'] = {
        'analyst_id': body.analyst_id,
        'notes': body.notes,
        'timeline_confirmed': body.timeline_confirmed,
        'signed_off_at': signed_at,
        'status': 'signed_off',
    }
    _legacy_helper('_persist', _persist)(assessment_id, assessment)

    return JSONResponse({
        'status': 'ok',
        'cluster_id': cluster_id,
        'signed_off_at': signed_at,
        'report_url': None,  # PDF export: v2
    })


@router.post('/{assessment_id}/clusters/{cluster_id}/further-tasks')
async def generate_further_tasks(
    assessment_id: str,
    cluster_id: str,
    body: FurtherTasksRequest,
    request: Request,
) -> JSONResponse:
    assessment = _legacy_helper('_get_assessment', _get_assessment)(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail='assessment_not_found')

    clusters = assessment.get('correlation_clusters') or []
    cluster = next((c for c in clusters if c.get('cluster_id') == cluster_id), None)
    if not cluster:
        raise HTTPException(status_code=404, detail='cluster_not_found')

    tenant_id = _get_tenant(request)

    # Gather all rows for this cluster
    all_rows = (assessment.get('normalized_rows') or
                assessment.get('evidence_rows') or
                assessment.get('rows') or [])
    row_refs = set(cluster.get('row_refs') or [])
    cluster_rows = [r for r in all_rows
                    if r.get('row_index') in row_refs or r.get('row_number') in row_refs]

    # Uncovered = cluster rows whose index is not in completed_evidence_refs
    completed = set(body.completed_evidence_refs)
    uncovered = [
        r for r in cluster_rows
        if (r.get('row_index') not in completed and
            r.get('row_number') not in completed)
    ]

    # Missing sources from existing evidence quality field or derive from cluster
    missing_sources: list[str] = (
        cluster.get('missing_sources') or
        cluster.get('evidence_gaps') or
        assessment.get('missing_sources') or
        []
    )

    # Entity extraction for entity-pinning
    users, ips, hosts = set(), set(), set()
    for r in cluster_rows:
        for f in ('user', 'user_principal_name', 'username', 'account'):
            v = _safe_text(r.get(f)).strip()
            if v and v not in ('-', 'N/A', ''):
                users.add(v)
        for f in ('src_ip', 'source_ip', 'dst_ip'):
            v = _safe_text(r.get(f)).strip()
            if v and v not in ('-', 'N/A', ''):
                ips.add(v)
        for f in ('hostname', 'host', 'device_name'):
            v = _safe_text(r.get(f)).strip()
            if v and v not in ('-', 'N/A', ''):
                hosts.add(v)

    entities_allowed = {
        'users': sorted(users)[:8],
        'ips': sorted(ips)[:6],
        'hosts': sorted(hosts)[:6],
    }

    try:
        from src.prompts.tier1_cluster_prefill import build_further_tasks_prompt
    except ImportError:
        from prompts.tier1_cluster_prefill import build_further_tasks_prompt  # type: ignore

    cluster_sources = sorted({str(r.get('_source') or r.get('source') or '') for r in cluster_rows if r.get('_source') or r.get('source')})
    prompt = build_further_tasks_prompt(
        cluster=cluster,
        uncovered_rows=uncovered,
        missing_sources=missing_sources,
        completed_task_titles=body.completed_task_titles,
        entities_allowed=entities_allowed,
        cluster_sources=cluster_sources,
    )

    llm = _legacy_helper('_get_llm', _get_llm)(body.model)
    if not llm:
        return JSONResponse({
            'status': 'no_llm',
            'further_tasks': [],
            'uncovered_row_count': len(uncovered),
        })

    further_tasks: list[dict] = []
    try:
        resp = llm.generate(
            prompt=prompt,
            max_tokens=512,
            tenant_id=tenant_id,
            overrides={'timeout': 20},
            model=body.model,
        )
        raw = (resp.get('text') or resp.get('response') or
               resp.get('content') or '') if isinstance(resp, dict) else str(resp)
        raw = raw.strip()
        if raw.startswith('```'):
            raw = '\n'.join(l for l in raw.split('\n') if not l.strip().startswith('```'))
        parsed = json.loads(raw)
        candidate_tasks = parsed.get('further_tasks') or []

        # Validate grounding: each task must cite real uncovered rows or missing sources
        uncovered_indices = {
            r.get('row_index') for r in uncovered
            if r.get('row_index') is not None
        } | {
            r.get('row_number') for r in uncovered
            if r.get('row_number') is not None
        }
        missing_lower = {s.lower() for s in missing_sources}

        for task in candidate_tasks:
            refs = [r for r in (task.get('evidence_refs') or [])
                    if r in uncovered_indices]
            ms = task.get('missing_source') or ''
            grounded_by_missing = ms and ms.lower() in missing_lower

            if refs or grounded_by_missing:
                task['evidence_refs'] = refs  # strip any hallucinated refs
                further_tasks.append(task)
            else:
                logger.debug(
                    'further_tasks: dropped ungrounded task "%s" for cluster %s',
                    task.get('title', '?'), cluster_id,
                )

    except Exception as exc:
        logger.warning('further_tasks LLM failed for %s/%s: %s',
                       assessment_id, cluster_id, exc)
        return JSONResponse({
            'status': 'llm_error',
            'error': str(exc),
            'further_tasks': [],
        })

    return JSONResponse({
        'status': 'ok',
        'cluster_id': cluster_id,
        'further_tasks': further_tasks,
        'uncovered_row_count': len(uncovered),
        'grounded_count': len(further_tasks),
    })


# â”€â”€ E9: Kill-chain phase timeline â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.get('/{assessment_id}/clusters/{cluster_id}/timeline')
async def get_cluster_timeline(
    assessment_id: str,
    cluster_id: str,
) -> JSONResponse:
    """Return rows for this cluster tagged with kill-chain phase, sorted by timestamp."""
    assessment = _legacy_helper('_get_assessment', _get_assessment)(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail='assessment_not_found')

    clusters = assessment.get('correlation_clusters') or []
    cluster = next((c for c in clusters if c.get('cluster_id') == cluster_id), None)
    if not cluster:
        raise HTTPException(status_code=404, detail='cluster_not_found')

    all_rows = (assessment.get('normalized_rows') or
                assessment.get('evidence_rows') or
                assessment.get('rows') or [])
    refs = set(cluster.get('row_refs') or [])
    cluster_rows = [r for r in all_rows
                    if (r.get('row_index') in refs or r.get('row_number') in refs)]

    # Tag kill-chain phase and extract timestamp for sort
    _TS_FIELDS = (
        'timestamp_utc', 'date_utc', 'timestamp_iso', 'source_time',
        'ts', 'timestamp', 'eventTime', 'time', 'createdDateTime',
        'activityDateTime', 'TimeGenerated', 'start', 'date',
        'datetime', '@timestamp', 'event_time', 'UpdatedDateTime',
    )
    tagged: list[dict] = []
    for r in cluster_rows:
        ts_val = None
        for tf in _TS_FIELDS:
            v = r.get(tf)
            if v is not None:
                ts_val = v
                break
        geo_asn = _row_geo_asn(r)
        tagged.append({
            'row_index': r.get('row_index') if 'row_index' in r else r.get('row_number'),
            'severity': r.get('severity') or r.get('risk_level') or 'info',
            'source': r.get('_source') or r.get('source') or '',
            'description': str(r.get('description') or r.get('activityDisplayName') or
                               r.get('operationName') or r.get('analyst_notes') or '')[:200],
            'mitre_technique': r.get('mitre_technique') or r.get('technique_id') or '',
            'kill_chain_phase': tag_kill_chain_phase(r),
            'user': r.get('user') or r.get('user_principal_name') or '',
            'src_ip': r.get('src_ip') or r.get('source_ip') or '',
            'hostname': r.get('hostname') or r.get('host') or '',
            'timestamp_raw': ts_val,
            'country': geo_asn['country'],
            'asn': geo_asn['asn'],
            'asn_org': geo_asn['asn_org'],
        })

    # Sort: rows with timestamps first (ascending), then un-timestamped
    def _ts_sort_key(row: dict):
        v = row['timestamp_raw']
        if v is None:
            return (1, 0)
        if isinstance(v, (int, float)):
            return (0, float(v) * 1000 if v < 1e12 else float(v))
        try:
            from datetime import datetime, timezone
            dt = datetime.fromisoformat(str(v).replace('Z', '+00:00'))
            return (0, dt.timestamp() * 1000)
        except Exception:
            return (1, 0)

    tagged.sort(key=_ts_sort_key)

    # Annotate rows where the ASN appears in 2+ distinct kill-chain phases
    _asn_phase_sets: dict[str, set[str]] = {}
    for row in tagged:
        asn = row.get('asn', '')
        if asn:
            _asn_phase_sets.setdefault(asn, set()).add(row['kill_chain_phase'])
    _reused_asns = {asn for asn, ps in _asn_phase_sets.items() if len(ps) >= 2}
    for row in tagged:
        row['_asn_reused'] = bool(row.get('asn') and row['asn'] in _reused_asns)

    # Group by kill-chain phase in order
    phases: dict[str, list] = {}
    for row in tagged:
        phase = row['kill_chain_phase']
        phases.setdefault(phase, []).append(row)

    ordered_phases = []
    for phase in _PHASE_ORDER + ['Unknown']:
        if phase in phases:
            ordered_phases.append({'phase': phase, 'rows': phases[phase]})

    return JSONResponse({
        'assessment_id': assessment_id,
        'cluster_id': cluster_id,
        'rows': tagged,
        'phases': ordered_phases,
        'total': len(tagged),
    })


# â”€â”€ E10: Analyst sticky notes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.patch('/{assessment_id}/clusters/{cluster_id}/notes')
async def patch_cluster_notes(
    assessment_id: str,
    cluster_id: str,
    body: NotesRequest,
) -> JSONResponse:
    assessment = _legacy_helper('_get_assessment', _get_assessment)(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail='assessment_not_found')

    clusters = assessment.get('correlation_clusters') or []
    cluster = next((c for c in clusters if c.get('cluster_id') == cluster_id), None)
    if not cluster:
        raise HTTPException(status_code=404, detail='cluster_not_found')

    cluster['analyst_notes'] = {
        'text': body.notes,
        'analyst_id': body.analyst_id,
        'updated_at': int(time.time()),
    }
    _legacy_helper('_persist', _persist)(assessment_id, assessment)

    return JSONResponse({
        'status': 'ok',
        'cluster_id': cluster_id,
        'updated_at': cluster['analyst_notes']['updated_at'],
    })


# â”€â”€ E11: IOC bundle (served; client can also build this locally) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.get('/{assessment_id}/clusters/{cluster_id}/iocs')
async def get_cluster_iocs(
    assessment_id: str,
    cluster_id: str,
) -> JSONResponse:
    assessment = _legacy_helper('_get_assessment', _get_assessment)(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail='assessment_not_found')

    clusters = assessment.get('correlation_clusters') or []
    cluster = next((c for c in clusters if c.get('cluster_id') == cluster_id), None)
    if not cluster:
        raise HTTPException(status_code=404, detail='cluster_not_found')

    all_rows = (assessment.get('normalized_rows') or
                assessment.get('evidence_rows') or
                assessment.get('rows') or [])
    refs = set(cluster.get('row_refs') or [])
    cluster_rows = [r for r in all_rows
                    if (r.get('row_index') in refs or r.get('row_number') in refs)]

    iocs = _extract_iocs(cluster, cluster_rows)
    iocs['exported_at'] = int(time.time())
    return JSONResponse(iocs)


# â”€â”€ E12: Repeat entity detection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.get('/{assessment_id}/clusters/{cluster_id}/repeat-entities')
async def get_repeat_entities(
    assessment_id: str,
    cluster_id: str,
) -> JSONResponse:
    """Scan all stored assessments for clusters sharing entities with this cluster."""
    assessment = _legacy_helper('_get_assessment', _get_assessment)(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail='assessment_not_found')

    clusters = assessment.get('correlation_clusters') or []
    cluster = next((c for c in clusters if c.get('cluster_id') == cluster_id), None)
    if not cluster:
        raise HTTPException(status_code=404, detail='cluster_not_found')

    all_rows = (assessment.get('normalized_rows') or
                assessment.get('evidence_rows') or
                assessment.get('rows') or [])
    refs = set(cluster.get('row_refs') or [])
    cluster_rows = [r for r in all_rows
                    if (r.get('row_index') in refs or r.get('row_number') in refs)]

    current_iocs = _extract_iocs(cluster, cluster_rows)
    current_entities: set[str] = set(
        current_iocs['users'] + current_iocs['ips'] + current_iocs['hosts']
    )

    if not current_entities:
        return JSONResponse({'matches': [], 'current_entity_count': 0})

    matches: list[dict] = []
    try:
        from src.api.deep_analyze_endpoints import REPORT_STORE
        for past_aid, past_assessment in list(REPORT_STORE.items()):
            if past_aid == assessment_id:
                continue
            past_clusters = past_assessment.get('correlation_clusters') or []
            past_rows = (past_assessment.get('normalized_rows') or
                         past_assessment.get('rows') or [])
            for pc in past_clusters:
                pc_refs = set(pc.get('row_refs') or [])
                pc_rows = [r for r in past_rows
                           if (r.get('row_index') in pc_refs or r.get('row_number') in pc_refs)]
                pc_iocs = _extract_iocs(pc, pc_rows)
                past_entities: set[str] = set(
                    pc_iocs['users'] + pc_iocs['ips'] + pc_iocs['hosts']
                )
                shared = current_entities & past_entities
                if shared:
                    matches.append({
                        'past_assessment_id': past_aid,
                        'past_cluster_id': pc.get('cluster_id', ''),
                        'past_verdict': pc.get('verdict') or pc.get('final_verdict', ''),
                        'past_severity': pc.get('severity', ''),
                        'shared_entities': sorted(shared)[:10],
                        'shared_count': len(shared),
                    })
    except Exception as exc:
        logger.debug('repeat_entities scan failed: %s', exc)

    matches.sort(key=lambda m: m['shared_count'], reverse=True)
    return JSONResponse({
        'cluster_id': cluster_id,
        'current_entity_count': len(current_entities),
        'matches': matches[:10],
        'match_count': len(matches),
    })
