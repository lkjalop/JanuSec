"""Persona-aware forwarding + backlog report endpoints."""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Header, Request
from pydantic import BaseModel, Field

from src.api import decision_endpoints as decision_api
from src.api.actor_context import set_current_actor
from src.core.ranking.persona_forwarder import PersonaForwarder, RankedRow
from src.reporting.playbooks import map_actions_to_playbook
from src.reporting.schemas import ExplainabilityLevel, PersonaType
from src.api.metrics_init import ensure_metrics, _safe_counter
from src.api.tenant_helpers import resolve_tenant_id

ensure_metrics()
FORWARD_REQUESTS = _safe_counter('forward_requests_total', 'Total forward requests', ['persona']) if _safe_counter else None
FORWARD_CREATED_DECISIONS = _safe_counter('forward_created_decisions_total', 'Total created decision gates from forward', ['persona']) if _safe_counter else None
FORWARD_SUGGESTED_ACTIONS = _safe_counter('forward_suggested_actions_total', 'Total suggested actions produced', ['persona']) if _safe_counter else None


router = APIRouter(prefix='/api/v1', tags=['Forwarding'])
_FORWARDER = PersonaForwarder()


def _enforce_rows_tenant(request: Request | None, rows: List[Dict[str, Any]], tenant_hint: str | None = None) -> str | None:
    if request is None:
        return tenant_hint
    tenant_id = resolve_tenant_id(request, tenant_hint)
    if tenant_id:
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            row_tenant = row.get('tenant_id') or row.get('tenant') or row.get('org')
            if row_tenant and str(row_tenant) != str(tenant_id):
                raise HTTPException(status_code=403, detail='tenant_mismatch')
    return tenant_id


def _summary_text(row: Dict[str, Any]) -> str:
    for key in ('summary', 'llm_summary', 'raw_summary', 'description', 'narrative'):
        if row.get(key):
            return str(row.get(key))
    return ''


def _evidence_refs(row: Dict[str, Any]) -> List[Any]:
    refs = row.get('evidence_refs') or row.get('evidence') or []
    if isinstance(refs, list):
        return refs
    if isinstance(refs, dict):
        return list(refs.values())
    return [refs] if refs else []


def _business_impact_high(row: Dict[str, Any]) -> bool:
    try:
        impact = row.get('impact_score')
        if impact is not None and float(impact) >= 0.7:
            return True
        est = row.get('estimated_cost')
        if est is not None and float(est) >= 10_000:
            return True
    except Exception:
        return False
    return False


def _tool_shortcuts(persona: PersonaType) -> Optional[List[Dict[str, str]]]:
    if persona != PersonaType.SOC_ANALYST:
        return None
    return [
        {'label': 'Isolate Host', 'action': 'isolate_host'},
        {'label': 'Block Indicator', 'action': 'block_indicator'},
        {'label': 'Create Ticket', 'action': 'create_ticket'},
    ]


def _factor_breakdown(row: Dict[str, Any]) -> Optional[List[Any]]:
    details = row.get('factor_breakdown') or row.get('factors')
    if not details:
        return None
    if isinstance(details, list):
        return details
    return [details]


def _prepare_item(entry: RankedRow, rank: int, persona: PersonaType) -> Dict[str, Any]:
    row = entry.row
    event_id = row.get('event_id') or row.get('row_index') or f'evt-{rank}'
    payload: Dict[str, Any] = {
        'event_id': event_id,
        'rank': rank,
        'score': entry.score,
        'triage_score': float(row.get('triage_score') or 0.0),
        'summary_text': _summary_text(row),
        'evidence_refs': _evidence_refs(row),
        'suggested_action': None,
        'decision_gate': None,
        'explainability': ExplainabilityLevel.SUMMARY.value,
        'tool_shortcuts': _tool_shortcuts(persona),
        'factor_breakdown': None,
        'features': entry.features,
    }
    # persona specific explainability
    if persona == PersonaType.EXECUTIVE:
        payload['explainability'] = ExplainabilityLevel.MINIMAL.value
    elif persona == PersonaType.THREAT_HUNTER:
        payload['explainability'] = ExplainabilityLevel.DETAILED.value
        payload['factor_breakdown'] = _factor_breakdown(row)
    else:
        payload['explainability'] = ExplainabilityLevel.SUMMARY.value
    # suggested action
    try:
        hints = {'actions': row.get('recommended_actions') or row.get('actions') or [], 'evidence_refs': payload['evidence_refs']}
        mapped = map_actions_to_playbook(hints)
        if not mapped:
            # fallback to LLM-assisted mapping if heuristics didn't pick
            try:
                from src.reporting.playbooks import map_actions_via_llm
                mapped = map_actions_via_llm(hints)
            except Exception:
                mapped = []
        if mapped:
            payload['suggested_action'] = mapped[0]
            try:
                if FORWARD_SUGGESTED_ACTIONS:
                    FORWARD_SUGGESTED_ACTIONS.inc(labels=[persona.value])
            except Exception:
                pass
    except Exception:
        payload['suggested_action'] = None
    return payload


def _maybe_open_decision_gate(item: Dict[str, Any], row: Dict[str, Any], persona: PersonaType, auto_create: bool) -> None:
    requires_budget = bool(row.get('decision_gate', {}).get('requires_budget')) or _business_impact_high(row)
    if persona != PersonaType.EXECUTIVE or not requires_budget:
        return
    if not auto_create:
        item['decision_gate'] = {'pending': True, 'reason': 'budget_approval_required'}
        return
    try:
        req = {
            'decision_type': 'budget',
            'persona': persona.value,
            'urgency': 'urgent',
            'question': f'Approve response budget for {item["event_id"]}',
            'context': item.get('summary_text') or 'Automated persona forwarder',
            'options': [{'label': 'Approve', 'id': 'approve'}, {'label': 'Defer', 'id': 'defer'}],
        }
        # Use actor-aware server wrapper to record who created the decision (actor could be passed in headers/UI)
        try:
            create_with_actor = getattr(decision_api, 'create_decision_with_actor', None)
        except Exception:
            create_with_actor = None
        prefer_plain = bool(
            __import__('os').getenv('FAST_TEST_MODE')
            or __import__('os').getenv('TEST_HELPERS_ENABLED')
            or 'PYTEST_CURRENT_TEST' in __import__('os').environ
        )
        if create_with_actor is not None and not prefer_plain:
            res = create_with_actor(req, actor=None)
        else:
            res = decision_api.create_decision(req)
        if not res or not res.get('gate_id'):
            try:
                res = decision_api.create_decision(req)
            except Exception:
                res = None
        if res and res.get('gate_id'):
            item['decision_gate'] = {'gate_id': res.get('gate_id'), 'status': 'created'}
            try:
                if FORWARD_CREATED_DECISIONS:
                    FORWARD_CREATED_DECISIONS.inc(labels=[persona.value])
            except Exception:
                pass
    except Exception:
        item['decision_gate'] = {'error': 'decision_gate_failed'}


def _forward_persona(rows: List[Dict[str, Any]], persona: PersonaType, top_n: int, *, auto_create_gate: bool = False) -> Dict[str, Any]:
    ranked = _FORWARDER.rank(rows, persona, top_n)
    results: List[Dict[str, Any]] = []
    for idx, entry in enumerate(ranked, start=1):
        row = entry.row
        item = _prepare_item(entry, idx, persona)
        _maybe_open_decision_gate(item, row, persona, auto_create_gate)
        results.append(item)
    return {'persona': persona.value, 'top_n': top_n, 'results': results}


class ForwardedItem(BaseModel):
    event_id: str
    rank: int
    score: float
    triage_score: float
    summary_text: str
    evidence_refs: List[Any]
    suggested_action: Optional[Dict[str, Any]]
    decision_gate: Optional[Dict[str, Any]]
    explainability: str
    tool_shortcuts: Optional[List[Dict[str, str]]]
    factor_breakdown: Optional[List[Any]]
    features: Optional[Dict[str, Any]]


class ForwardPersonaRequest(BaseModel):
    rows: List[Dict[str, Any]]
    persona: PersonaType = Field(PersonaType.SOC_ANALYST)
    top_n: int = Field(5, ge=1, le=50)
    auto_create_gate: bool = Field(False, description='Automatically create DecisionGate entries when required (executive persona only).')


class ForwardPersonaResponse(BaseModel):
    persona: str = Field(..., json_schema_extra={'example': 'soc_analyst'})
    top_n: int = Field(..., json_schema_extra={'example': 5})
    results: List[ForwardedItem]


@router.post('/forwarding/persona', summary='Rank and forward rows for a given persona', response_model=ForwardPersonaResponse, operation_id='forwarding_persona')
@router.post('/forward/rank_and_forward', include_in_schema=False, operation_id='forward_rank_and_forward')
def persona_forward(req: ForwardPersonaRequest, request: Request, x_actor: Optional[str] = Header(None, convert_underscores=False)) -> Dict[str, Any]:
    if not isinstance(req.rows, list):
        raise HTTPException(status_code=400, detail='invalid_rows')
    _enforce_rows_tenant(request, req.rows)
    try:
        if FORWARD_REQUESTS:
            FORWARD_REQUESTS.inc(labels=[req.persona.value])
    except Exception:
        pass
    # Actor header middleware sets per-request actor; no explicit context needed here.
    return _forward_persona(req.rows, req.persona, req.top_n, auto_create_gate=req.auto_create_gate)


class ForwardAndCreateRequest(BaseModel):
    rows: List[Dict[str, Any]]
    persona: PersonaType = Field(PersonaType.SOC_ANALYST)
    top_n: int = Field(5, ge=1, le=50)


class ForwardAndCreateResponse(BaseModel):
    persona: str = Field(..., json_schema_extra={'example': 'executive'})
    top_n: int = Field(..., json_schema_extra={'example': 3})
    results: List[ForwardedItem]
    created_gate_ids: List[str]


@router.post('/forwarding/persona/execute', summary='Rank rows and auto-create DecisionGates where necessary', response_model=ForwardAndCreateResponse, operation_id='forwarding_persona_execute')
@router.post('/forward/forward_and_create', include_in_schema=False, operation_id='forward_forward_and_create')
def forward_and_create(req: ForwardAndCreateRequest, request: Request, x_actor: Optional[str] = Header(None, convert_underscores=False)) -> Dict[str, Any]:
    try:
        if FORWARD_REQUESTS:
            FORWARD_REQUESTS.inc(labels=[req.persona.value])
    except Exception:
        pass
    _enforce_rows_tenant(request, req.rows)
    # Rely on middleware to set actor; execute forwarding normally
    resp = _forward_persona(req.rows, req.persona, req.top_n, auto_create_gate=True)
    created = [item.get('decision_gate', {}).get('gate_id') for item in resp.get('results', []) if item.get('decision_gate', {}).get('gate_id')]
    resp['created_gate_ids'] = [gid for gid in created if gid]
    try:
        if FORWARD_CREATED_DECISIONS:
            FORWARD_CREATED_DECISIONS.inc(labels=[req.persona.value], amount=len(resp['created_gate_ids']))
    except Exception:
        pass
    return resp


def _not_investigated(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    pending = []
    for row in rows:
        status = row.get('status')
        pipeline_done = row.get('_pipeline_done')
        human_verified = row.get('human_verified')
        if (status != 'ready' and not pipeline_done) or (human_verified is False):
            pending.append(row)
    return pending


class BacklogRequest(BaseModel):
    rows: List[Dict[str, Any]]


class BacklogResponse(BaseModel):
    persona: str
    not_investigated: int
    not_investigated_count: int
    triage_buckets: Dict[str, int]
    top_factors: List[Dict[str, Any]]
    age_stats: Dict[str, Optional[float]]
    prioritization: List[Dict[str, Any]]


@router.post('/forwarding/backlog', summary='Aggregate backlog insight for prioritization', response_model=BacklogResponse, operation_id='forwarding_backlog')
@router.post('/forward/backlog_report', include_in_schema=False, operation_id='forward_backlog_report')
def backlog_report(req: BacklogRequest, request: Request, persona: PersonaType = PersonaType.SOC_ANALYST) -> Dict[str, Any]:
    rows = req.rows or []
    _enforce_rows_tenant(request, rows)
    pending = _not_investigated(rows)
    now = time.time()
    ranked = _FORWARDER.rank(pending, persona, top_n=len(pending), now_ts=now)
    triage_buckets = {'0.75+': 0, '0.5-0.75': 0, '0.25-0.5': 0, '<0.25': 0}
    factor_counts: Dict[str, int] = {}
    ages: List[float] = []
    prioritization: List[Dict[str, Any]] = []
    for idx, entry in enumerate(ranked, start=1):
        tri = float(entry.row.get('triage_score') or 0.0)
        if tri >= 0.75:
            triage_buckets['0.75+'] += 1
        elif tri >= 0.5:
            triage_buckets['0.5-0.75'] += 1
        elif tri >= 0.25:
            triage_buckets['0.25-0.5'] += 1
        else:
            triage_buckets['<0.25'] += 1
        for factor in entry.row.get('factors') or []:
            factor_counts[factor] = factor_counts.get(factor, 0) + 1
        ts = entry.row.get('ingested_ts') or entry.row.get('created_ts') or now
        try:
            ages.append(max(0.0, now - float(ts)))
        except Exception:
            continue
        if idx <= 10:
            sla = 'High-priority backlog; run deep analyze / contain' if tri >= 0.75 else 'Review within SLA'
            prioritization.append({
                'event_id': entry.row.get('event_id') or entry.row.get('row_index') or f'evt-{idx}',
                'triage_score': tri,
                'score': entry.score,
                'suggestion': 'Trigger one-click contain' if tri >= 0.85 else 'Run deep analyze',
                'sla': sla,
            })
    age_stats = {
        'min_minutes': round(min(ages) / 60, 2) if ages else None,
        'max_minutes': round(max(ages) / 60, 2) if ages else None,
        'avg_minutes': round((sum(ages) / len(ages)) / 60, 2) if ages else None,
    }
    top_factors = sorted(factor_counts.items(), key=lambda item: item[1], reverse=True)[:10]
    return {
        'persona': persona.value,
        'not_investigated': len(pending),
        'not_investigated_count': len(pending),
        'triage_buckets': triage_buckets,
        'top_factors': [{'factor': k, 'count': v} for k, v in top_factors],
        'age_stats': age_stats,
        'prioritization': prioritization,
    }
