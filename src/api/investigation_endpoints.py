"""Investigation endpoints: lightweight active state + on-demand multi-log request.

Adds POST /api/v1/investigations/request that orchestrates a targeted
multi-source correlation build using existing graph session helpers. This
endpoint is intentionally pragmatic: it accepts a suspicion-driven payload,
produces two or more synthetic/collected batches when necessary, and returns
ranked evidence with capture suggestions, expected costs, and privacy notes.
"""
from __future__ import annotations

from typing import Optional, Any, Dict, List, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field

from .dependencies import get_platform_state
from .state import PlatformState
from .tenant_helpers import resolve_tenant_id

# Reuse graph session helpers for correlation, overlap matrices, and mapping stats
try:
    # Prefer function form that returns a structured response
    from .graph_session_endpoints import build_session_response as _build_graph_session  # type: ignore
except Exception:  # pragma: no cover - fallback if import path changes
    _build_graph_session = None  # type: ignore

router = APIRouter(tags=["Investigation"])

@router.get('/api/v1/investigation/active')
async def investigation_active(tenant_id: str | None = Header(None, alias='X-Tenant-ID'), request: Request = None, state: PlatformState = Depends(get_platform_state)):
    tenant_id = resolve_tenant_id(request, tenant_id)
    # Attempt to leverage recent alerts as active investigation heuristic
    alerts = state.recent_alerts(limit=50, tenant_id=tenant_id)
    crit = [a for a in alerts if getattr(a,'verdict','').lower() in ('malicious','block','escalate') and getattr(a,'score',0)>=0.8]
    if not crit:
        return {
            'investigation_id': None,
            'target': None,
            'sha256': None,
            'first_seen': None,
            'affected_hosts': [],
            'mitre_techniques': [],
            'status': 'idle',
            'tenant_id': tenant_id,
        }
    a = crit[0]
    return {
        'investigation_id': f"inv-{a.id}",
        'target': getattr(a,'process_name', None) or getattr(a,'filename', None) or 'unknown',
        'sha256': getattr(a,'hash', None),
        'first_seen': getattr(a,'ts', None),
        'affected_hosts': [h for h in [getattr(a,'host', None)] if h],
        'mitre_techniques': ['T1059','T1105'],
        'status': 'active',
        'severity': 'critical',
        'confidence': getattr(a,'score', None),
        'tenant_id': tenant_id,
    }

__all__ = ['router']


# ------------------------------
# Investigation Request Orchestrator
# ------------------------------

class TimeWindow(BaseModel):
    start: Optional[str] = Field(default=None, description="ISO8601 start time")
    end: Optional[str] = Field(default=None, description="ISO8601 end time")
    last: Optional[str] = Field(default=None, description="Relative window e.g. -15m, -1h")


class InvestigationRequest(BaseModel):
    reason: Optional[str] = Field(default=None, description="Analyst reason / suspicion")
    entities: Optional[Dict[str, Any]] = Field(default=None, description="Suspect entities: user/host/ip/domain/file_hash/process/email/cloud/service")
    suspected_tactics: Optional[List[str]] = Field(default=None, description="MITRE tactics/techniques hints")
    assets: Optional[List[str]] = Field(default=None, description="Critical assets or scopes (pods, subnets, hosts)")
    scope: Optional[str] = Field(default=None, description="Scope hint: endpoint|network|identity|cloud|k8s|all")
    time_window: Optional[TimeWindow] = None
    # Optional inline sessions or ids to directly correlate
    sessions: Optional[List[Dict[str, Any]]] = None
    session_ids: Optional[List[str]] = None
    # Graph options
    ewma: Optional[bool] = True
    ewma_alpha: Optional[float] = None


def _synthesize_minimal_sessions(entities: Optional[Dict[str, Any]]) -> List[Tuple[str, Dict[str, Any]]]:
    """Create at least two lightweight sessions from provided entities so the
    correlator can run even if upstream fetchers are not wired.
    """
    e = entities or {}
    # Split by coarse domain to encourage some overlap
    sess_a = {
        'id': 'hint-entities',
        'data': {
            'entities': {
                'user': e.get('user') or e.get('account'),
                'host': e.get('host'),
                'process': e.get('process') or e.get('cmd'),
                'file_hash': e.get('file_hash') or e.get('sha256') or e.get('sha1') or e.get('md5'),
                'domain': e.get('domain') or e.get('fqdn'),
                'ip': e.get('ip') or e.get('src_ip') or e.get('dst_ip'),
            }
        }
    }
    sess_b = {
        'id': 'expanded-hypothesis',
        'data': {
            'entities': {
                'user': e.get('alt_user') or e.get('user'),
                'host': e.get('alt_host') or e.get('host'),
                'process': e.get('child_process') or e.get('process'),
                'file_hash': e.get('artifact') or e.get('file_hash'),
                'domain': e.get('related_domain') or e.get('domain'),
                'ip': e.get('related_ip') or e.get('ip'),
            }
        }
    }
    return [(sess_a['id'], sess_a), (sess_b['id'], sess_b)]


def _make_capture_suggestions(confidence: float, scope: Optional[str]) -> List[Dict[str, Any]]:
    """Return capture/action suggestions with costs and privacy notes."""
    high_risk = confidence >= 0.6
    suggest: List[Dict[str, Any]] = []
    # eBPF syscall subset
    suggest.append({
        'action': 'capture_ebpf_syscalls',
        'duration': '10m',
        'when': 'on_approval' if not high_risk else 'recommended',
        'expected_cost': {'cpu': '~1-2% per node', 'storage': 'low'},
        'privacy_notes': 'May include process args; enable redaction policies',
        'scope': scope or 'endpoint/k8s'
    })
    # PCAP short capture
    suggest.append({
        'action': 'capture_pcap',
        'duration': '5m',
        'when': 'analyst_request' if not high_risk else 'consider',
        'expected_cost': {'storage': '50-150MB / 5m', 'cpu': 'low-medium'},
        'privacy_notes': 'Contains payloads; scope tightly and mask PII',
        'scope': scope or 'network/chokepoint'
    })
    return suggest


def _consensus_gate(mapping_stats: Dict[str, int], corr_nonzero_pairs: int) -> Dict[str, Any]:
    # Simple consensus: require two independent domains present and at least one non-zero pair
    domains_present = sum(1 for k in ['user','host','ip','domain','file_hash','process'] if (mapping_stats.get(k,0) or 0) > 0)
    ok = (domains_present >= 2) and (corr_nonzero_pairs > 0)
    return {'meets_consensus': ok, 'domains_present': domains_present}


@router.post('/api/v1/investigations/request')
async def investigations_request(req: Request, state: PlatformState = Depends(get_platform_state)):
    tenant_id = resolve_tenant_id(req, None)
    try:
        body = await req.json()
    except Exception:
        raise HTTPException(status_code=400, detail='invalid_json')
    try:
        payload = InvestigationRequest.model_validate(body)
    except Exception as e:  # 422
        raise HTTPException(status_code=422, detail=str(e))

    # Build sessions input from inline sessions/ids or synthesize from entities
    sessions_input: List[Tuple[str, Dict[str, Any]]] = []
    # Inline sessions passed by client
    built_sessions = []
    if payload.sessions:
        for s in payload.sessions:
            sid = s.get('id') or f"inline-{len(sessions_input)}"
            sessions_input.append((sid, s))
    # Minimal synthesis when we don't have at least 2
    if len(sessions_input) < 2:
        sessions_input.extend(_synthesize_minimal_sessions(payload.entities))
    
    # Build-orchestrate: collect sessions from provided IDs or on-demand lines
    session_ids = payload.session_ids or []
    if (not session_ids) and (getattr(payload, 'seed_lines', None)):
        try:
            from src.api.on_demand_fetch_endpoints import build_session_from_lines
        except Exception:
            build_session_from_lines = None  # type: ignore
        if build_session_from_lines:
            filters = payload.entities or {}
            sid, sess = build_session_from_lines(
                getattr(payload, 'seed_source', 'zeek'),
                getattr(payload, 'seed_kind', None),
                getattr(payload, 'seed_lines', []),
                filters,
            )
            built_sessions.append(sess)
            sessions_input.append((sid, sess))
    
    if not session_ids and not sessions_input:
        # synthesize a minimal placeholder session from provided entities for correlation baseline
        sid = f"batch-investigation-{int(__import__('time').time())}"
        minimal_session = {
            'id': sid,
            'data': {
                'entities': payload.entities or {},
                'events': [],
            }
        }
        sessions_input.append((sid, minimal_session))
        try:
            from src.api.graph_sessions import _persist_session
        except Exception:
            _persist_session = None
        if _persist_session:
            await _persist_session(minimal_session)  # type: ignore
    # Persist any built sessions to align with TTL/cleanup
    try:
        from src.api.graph_sessions import _persist_session as __persist
    except Exception:
        __persist = None
    if __persist:
        for sid, sess in sessions_input:
            try:
                await __persist(sess)  # type: ignore
            except Exception:
                pass
    # Try building default source sessions when we still have fewer than 2
    if len(sessions_input) < 2 and payload.entities:
        try:
            from src.api.on_demand_fetch_endpoints import build_session_from_source
        except Exception:
            build_session_from_source = None  # type: ignore
        if build_session_from_source:
            filters = payload.entities
            for src in ('zeek','sysmon'):
                sid, sess = build_session_from_source(src, filters, payload.time_window, getattr(payload, 'seed_kind', None), 50)
                sessions_input.append((sid, sess))

    # Build correlation via graph session helper
    if not _build_graph_session:
        raise HTTPException(status_code=500, detail='graph_session_helper_unavailable')

    built = _build_graph_session(sessions_input, {
        'ewma': bool(payload.ewma if payload.ewma is not None else True),
        'ewma_alpha': payload.ewma_alpha
    })

    mapping_stats: Dict[str, int] = built.get('mapping_stats') or {}
    corr = built.get('correlation') or []
    nonzero_pairs = int(built.get('overlap_summary', {}).get('nonzero_pairs', 0))
    consensus = _consensus_gate(mapping_stats, nonzero_pairs)

    # Top evidence (pivot points + centrality)
    pivots = built.get('pivot_points') or []
    centrality = built.get('entity_centrality') or {}
    top_entities = sorted(centrality.items(), key=lambda kv: kv[1], reverse=True)[:6]
    ranked_evidence = [{ 'entity': k, 'degree': v } for k,v in top_entities]

    # Next-best-evidence suggestions (reuse mapping coverage heuristics)
    next_best: List[Dict[str, Any]] = []
    try:
        # Lightweight heuristic: suggest logs for low-count canonical fields
        for field, label in [('user','Authentication/IdP'),('host','Endpoint/EDR'),('ip','NetFlow/DNS'),('domain','DNS/Proxy'),('file_hash','EDR file events')]:
            cnt = int(mapping_stats.get(field, 0) or 0)
            if cnt == 0:
                next_best.append({'missing': field, 'suggest': label, 'priority': 'high'})
            elif cnt < 3:
                next_best.append({'weak': field, 'suggest': label, 'priority': 'medium'})
    except Exception:
        pass

    confidence = float(built.get('confidence') or 0.0)
    capture_suggestions = _make_capture_suggestions(confidence, payload.scope)

    response = {
        'tenant_id': tenant_id,
        'reason': payload.reason,
        'summary': {
            'verdict': built.get('verdict') or 'info',
            'confidence': confidence,
            'consensus': consensus,
            'overlap': built.get('overlap_summary'),
        },
        'ranked_evidence': ranked_evidence or pivots,
        'next_best_evidence': next_best,
        'capture_suggestions': capture_suggestions,
        'expected_costs': {
            'ebpf': 'CPU ~1-2%/node for subset; minimal storage',
            'pcap': '50-150MB per 5m capture @ 1Gbps typical'
        },
        'privacy_notes': {
            'ebpf': 'Process args may include PII; enable redaction policies',
            'pcap': 'Payload data may contain PII; scope narrowly and mask'
        },
        'graph': built
    }
    return response
