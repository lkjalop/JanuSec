from fastapi import APIRouter, HTTPException, Depends, Header, Request
from pydantic import BaseModel
from typing import List, Tuple, Optional
from src.domains.iam.graph_store import PermissionGraphStore
from src.api.runtime_state import get_server_runtime_state, get_permission_graph
from src.domains.iam.privilege_escalation import reevaluate_on_iam_event
import time
from src.domains.iam.policy_ingest import parse_policy_document, parse_trust_policy, ingest_policy_to_graph
from src.api import iam_metrics
from src.api.tenant_helpers import resolve_tenant_id
from src.security.roles import require_roles, require_admin_dep


class IngestPolicyRequest(BaseModel):
    policy: dict
    principal_prefix: Optional[str] = None
    weight_overrides: Optional[dict] = None

router = APIRouter()


class UpsertPrincipalRequest(BaseModel):
    principal: str
    actions: List[Tuple[str, int]]


class AddEdgeRequest(BaseModel):
    src: str
    dst: str
    weight: Optional[float] = None


class EscalationQuery(BaseModel):
    start_principal: str
    target_level: int


# Simple runtime singleton for demo/test; in real app this should be attached to app state
_GRAPH = None  # legacy; prefer per-tenant graph via runtime_state


@router.post('/api/v1/iam/principal')
def upsert_principal(req: UpsertPrincipalRequest, request: Request, x_tenant_id: str | None = Header(None, alias='X-Tenant-Id')):
    runtime = get_server_runtime_state(request.app)
    tenant_id = resolve_tenant_id(request, x_tenant_id) or x_tenant_id
    graph = get_permission_graph(runtime, tenant_id)
    graph.upsert_principal(req.principal, req.actions)
    # best-effort: re-evaluate escalation risk for impacted principal
    try:
        runtime = get_server_runtime_state(request.app)
        # run synchronously; it's lightweight for small graphs
        try:
            reevaluate_on_iam_event({'requestParameters': {'user': req.principal}}, runtime=runtime, tenant_id=tenant_id, targets=[req.principal])
        except Exception:
            pass
    except Exception:
        pass
    return {'status': 'ok'}


@router.post('/api/v1/iam/edge')
def add_edge(req: AddEdgeRequest, request: Request, x_tenant_id: str | None = Header(None, alias='X-Tenant-Id')):
    if req.src == req.dst:
        raise HTTPException(status_code=400, detail='src and dst must differ')
    runtime = get_server_runtime_state(request.app)
    tenant_id = resolve_tenant_id(request, x_tenant_id) or x_tenant_id
    graph = get_permission_graph(runtime, tenant_id)
    if req.weight is None:
        graph.add_edge(req.src, req.dst)
    else:
        graph.add_weighted_edge(req.src, req.dst, req.weight)
    # best-effort re-eval for src and dst
    try:
        runtime = get_server_runtime_state(request.app)
        try:
            reevaluate_on_iam_event({'requestParameters': {'user': req.dst}, 'userIdentity': {'userName': req.src}}, runtime=runtime, tenant_id=tenant_id, targets=[req.src, req.dst])
        except Exception:
            pass
    except Exception:
        pass
    return {'status': 'ok'}


@router.post('/api/v1/iam/escalation')
def query_escalation(req: EscalationQuery, request: Request, x_tenant_id: str | None = Header(None, alias='X-Tenant-Id')):
    runtime = get_server_runtime_state(request.app)
    tenant_id = resolve_tenant_id(request, x_tenant_id) or x_tenant_id
    graph = get_permission_graph(runtime, tenant_id)
    res = graph.find_shortest_escalation_path(req.start_principal, req.target_level)
    if not res:
        raise HTTPException(status_code=404, detail='no escalation path found')
    return res


@router.post('/api/v1/iam/escalation/risk')
def query_escalation_risk(req: EscalationQuery, request: Request, x_tenant_id: str | None = Header(None, alias='X-Tenant-Id')):
    runtime = get_server_runtime_state(request.app)
    tenant_id = resolve_tenant_id(request, x_tenant_id) or x_tenant_id
    graph = get_permission_graph(runtime, tenant_id)
    res = graph.find_risk_weighted_path(req.start_principal, req.target_level)
    if not res:
        raise HTTPException(status_code=404, detail='no escalation path found')
    return res


class FeedbackRecord(BaseModel):
    principal: str
    action: str
    verdict: str
    comment: Optional[str] = None


@router.post('/api/v1/iam/feedback')
def record_feedback(rec: FeedbackRecord, request: Request, x_tenant_id: str | None = Header(None, alias='X-Tenant-Id')):
    runtime = get_server_runtime_state(request.app)
    tid = resolve_tenant_id(request, x_tenant_id) or x_tenant_id or 'global'
    tmap = runtime.tenants.get(tid)
    if tmap is None:
        tmap = get_server_runtime_state(request.app).tenants.setdefault(tid, {})
    feedback = tmap.setdefault('iam_feedback', [])
    entry = {'ts': time.time(), 'principal': rec.principal, 'action': rec.action, 'verdict': rec.verdict, 'comment': rec.comment}
    feedback.append(entry)
    # Persist tenant runtime best-effort
    try:
        from src.api.runtime_state import persist_tenant_runtime
        persist_tenant_runtime(runtime, tid)
    except Exception:
        pass
    # metrics
    try:
        iam_metrics.incr_feedback(tid, rec.verdict or 'unknown')
    except Exception:
        pass
    return {'status': 'ok'}


@router.post('/api/v1/iam/ingest_policy')
def ingest_policy(req: IngestPolicyRequest, request: Request, x_tenant_id: str | None = Header(None, alias='X-Tenant-Id')):
    runtime = get_server_runtime_state(request.app)
    tenant_id = resolve_tenant_id(request, x_tenant_id) or x_tenant_id
    graph = get_permission_graph(runtime, tenant_id)
    try:
        # Load tenant-level overrides and merge with request overrides
        tid = tenant_id or 'global'
        tmap = runtime.tenants.setdefault(tid, {})
        tenant_overrides = tmap.get('iam_weight_overrides', {}) or {}
        # request overrides take precedence
        merged_overrides = dict(tenant_overrides)
        if getattr(req, 'weight_overrides', None):
            try:
                merged_overrides.update(req.weight_overrides or {})
            except Exception:
                pass
        ingest_policy_to_graph(graph, req.policy, principal_prefix=(req.principal_prefix or ''), weight_overrides=merged_overrides)
        # Basic mapping: convert action strings like 'iam:CreateAccessKey' to levels
        # For demo: use privilege_escalation.action_permission_level when possible
        from src.domains.iam.privilege_escalation import action_permission_level
        # Normalize actions in graph to proper levels
        for p, acts in list(graph.actions.items()):
            norm = []
            for a, _ in acts:
                lvl = action_permission_level(a)
                norm.append((a, lvl))
            graph.actions[p] = norm
    except Exception as e:
        raise HTTPException(status_code=400, detail=f'ingest_failed:{e}')
    # persist eval and re-evaluate impacted principals
    try:
        reevaluate_on_iam_event({'requestParameters': {'user': 'policy_ingest'}}, runtime=runtime, tenant_id=tenant_id)
    except Exception:
        pass
    return {'status': 'ok'}


class CloudAuditRecord(BaseModel):
    event: dict


@router.post('/api/v1/iam/cloud_audit')
def ingest_cloud_audit(rec: CloudAuditRecord, request: Request, x_tenant_id: str | None = Header(None, alias='X-Tenant-Id')):
    """Accept cloud provider audit logs (identity-related) and feed into correlation/reeval.

    Example: POST body {"event": { ... cloudtrail / audit event ... }}
    """
    runtime = get_server_runtime_state(request.app)
    tenant_id = resolve_tenant_id(request, x_tenant_id) or x_tenant_id
    # best-effort: correlate to principals and re-evaluate
    try:
        # crude extraction of principal
        ev = rec.event or {}
        user = ev.get('userIdentity', {}).get('userName') or ev.get('userIdentity', {}).get('arn')
        targets = [user] if user else None
        # call reevaluation synchronously for now
        reevaluate_on_iam_event(ev, runtime=runtime, tenant_id=tenant_id, targets=targets)
    except Exception:
        pass
    return {'status': 'ok'}


class WeightOverridesReq(BaseModel):
    overrides: dict


@router.post('/api/v1/iam/admin/set_weight_overrides')
def set_weight_overrides(req: WeightOverridesReq, request: Request, x_tenant_id: str | None = Header(None, alias='X-Tenant-Id'), auth=Depends(require_admin_dep)):
    # Persist tenant-level IAM weight overrides used by ingest pipeline
    runtime = get_server_runtime_state(request.app)
    tid = resolve_tenant_id(request, x_tenant_id) or x_tenant_id or 'global'
    tmap = runtime.tenants.setdefault(tid, {})
    tmap['iam_weight_overrides'] = req.overrides or {}
    # persist runtime
    try:
        from src.api.runtime_state import persist_tenant_runtime
        persist_tenant_runtime(runtime, tid)
    except Exception:
        pass
    return {'status': 'ok'}


@router.get('/api/v1/iam/admin/get_weight_overrides', operation_id='iam_admin_get_weight_overrides')
def get_weight_overrides(request: Request, x_tenant_id: str | None = Header(None, alias='X-Tenant-Id'), auth=Depends(require_admin_dep)):
    runtime = get_server_runtime_state(request.app)
    tid = resolve_tenant_id(request, x_tenant_id) or x_tenant_id or 'global'
    tmap = runtime.tenants.get(tid, {})
    return {'overrides': tmap.get('iam_weight_overrides', {})}
