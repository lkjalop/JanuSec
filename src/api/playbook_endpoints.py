"""Playbook lookup endpoints (canonical router)."""
from __future__ import annotations
from fastapi import APIRouter, HTTPException, Header, Request
from pathlib import Path
import os
import yaml
try:
    from core.metrics.registry import metric_counter  # type: ignore
    _PB_HITS = metric_counter('playbook_db_hits_total', 'Playbook DB hit count')
    _PB_MISSES = metric_counter('playbook_db_misses_total', 'Playbook DB misses')
    _PB_RELOADS = metric_counter('playbook_db_reloads_total', 'Playbook DB reloads')
except Exception:
    _PB_HITS = _PB_MISSES = _PB_RELOADS = None

router_playbook_single = APIRouter(prefix="/api/v1/playbook", tags=["Playbooks"])
from .tenant_helpers import resolve_tenant_id

try:
    from src.analysis.playbook_db import get_playbook_for_mitre  # type: ignore
    from src.analysis.playbook_db import reload as reload_playbook_db  # type: ignore
except Exception:
    try:
        from ..analysis.playbook_db import get_playbook_for_mitre  # type: ignore
        from ..analysis.playbook_db import reload as reload_playbook_db  # type: ignore
    except Exception:
        get_playbook_for_mitre = None  # type: ignore
        reload_playbook_db = None  # type: ignore


@router_playbook_single.get("/{mitre_id}")
async def playbook_get(mitre_id: str, tenant_id: str | None = Header(None, alias='X-Tenant-ID'), request: Request = None) -> dict:
    tenant_id = resolve_tenant_id(request, tenant_id)
    if not get_playbook_for_mitre:
        raise HTTPException(status_code=500, detail='playbook_db_unavailable')
    try:
        pb = get_playbook_for_mitre(mitre_id.upper())
    except Exception:
        pb = None
    try:
        if pb and _PB_HITS:
            _PB_HITS.labels(mitre=mitre_id.upper()).inc()
        elif not pb and _PB_MISSES:
            _PB_MISSES.labels(mitre=mitre_id.upper()).inc()
    except Exception:
        pass
    if not pb:
        raise HTTPException(status_code=404, detail='playbook_not_found')
    out = dict(pb)
    if tenant_id:
        out['_tenant_id'] = tenant_id
    return out


@router_playbook_single.post('/reload')
async def playbook_reload_endpoint(x_admin_key: str | None = Header(None, alias='X-Admin-Key')) -> dict:
    expected = os.getenv('PLAYBOOK_ADMIN_KEY')
    if expected:
        if not x_admin_key or x_admin_key != expected:
            raise HTTPException(status_code=403, detail='forbidden')
    if not reload_playbook_db:
        raise HTTPException(status_code=500, detail='playbook_db_unavailable')
    try:
        reload_playbook_db()
        if _PB_RELOADS:
            _PB_RELOADS.labels().inc()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'reload_failed: {e}')
    return {'reloaded': True}
from typing import Any
from src.analysis.playbook_db import get_playbook_for_mitre, list_mitre_ids

router_playbook_root = APIRouter(prefix='/api/v1')


@router_playbook_root.get('/playbook/{mitre_id}')
async def get_playbook(mitre_id: str):
    mitre_id = (mitre_id or '').strip()
    if not mitre_id:
        raise HTTPException(status_code=400, detail='missing_mitre_id')
    pb = get_playbook_for_mitre(mitre_id)
    try:
        if pb and _PB_HITS:
            _PB_HITS.labels(mitre=mitre_id).inc()
        elif not pb and _PB_MISSES:
            _PB_MISSES.labels(mitre=mitre_id).inc()
    except Exception:
        pass
    if not pb:
        # return 404 with list of known IDs for discoverability
        known = list_mitre_ids()
        raise HTTPException(status_code=404, detail={'message': 'playbook_not_found', 'known_ids': known})
    return pb


@router_playbook_root.post('/playbook/reload')
async def post_playbook_reload(x_admin_key: str | None = Header(None, alias='X-Admin-Key')) -> dict:
    expected = os.getenv('PLAYBOOK_ADMIN_KEY')
    if expected:
        if not x_admin_key or x_admin_key != expected:
            raise HTTPException(status_code=403, detail='forbidden')
    if not reload_playbook_db:
        raise HTTPException(status_code=500, detail='playbook_db_unavailable')
    try:
        reload_playbook_db()
        if _PB_RELOADS:
            _PB_RELOADS.labels().inc()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'reload_failed: {e}')
    return {'reloaded': True}
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
from typing import Any, Dict, List
import time, uuid, json
from .taxonomy_mapper import enrich_graph_with_taxonomies
try:
    from src.soar.playbook_worker import dispatch_playbook
except Exception:
    from ..soar.playbook_worker import dispatch_playbook  # type: ignore

router_playbooks = APIRouter(prefix='/api/v1/playbooks', tags=['Playbooks'])

MEMORY_FACTOR_HINTS = {
    'memory:suspicious_injection',
    'memory:credential_dump',
    'memory:reflective_loader',
    'process_injection',
    'credential_dumping',
    'lsass_access',
}
MEMORY_MITRE_IDS = {'T1003', 'T1055', 'T1112'}


def _load_template_file(path: Path) -> Dict[str, Any] | None:
    try:
        if path.suffix.lower() in {'.yml', '.yaml'}:
            return yaml.safe_load(path.read_text(encoding='utf-8')) or {}
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return None


def _extract_graph_factors(graph: Dict[str, Any]) -> List[str]:
    factors: List[str] = []
    meta = graph.get('metadata')
    if isinstance(meta, dict):
        meta_factors = meta.get('factors')
        if isinstance(meta_factors, list):
            factors.extend([str(f) for f in meta_factors if f])
    raw = graph.get('factors')
    if isinstance(raw, list):
        factors.extend([str(f) for f in raw if f])
    return factors


def _graph_requires_memory(graph: Dict[str, Any], mitre_tags: List[str] | None) -> bool:
    factors = {f.lower() for f in _extract_graph_factors(graph)}
    if any(f.startswith('memory:') or f in MEMORY_FACTOR_HINTS for f in factors):
        return True
    mitre_upper = {str(mid).upper() for mid in (mitre_tags or []) if mid}
    if mitre_upper.intersection(MEMORY_MITRE_IDS):
        return True
    metadata = graph.get('metadata') or {}
    enrichment = metadata.get('enrichment') if isinstance(metadata, dict) else {}
    if isinstance(enrichment, dict):
        forensics = enrichment.get('forensics')
        if isinstance(forensics, dict):
            if forensics.get('memory_required') or forensics.get('needs_memory'):
                return True
    return False

class PlaybookRequest(BaseModel):
    graph: Dict[str, Any] | None = None
    session_ids: List[str] | None = None
    mitre_techniques: List[str] | None = None
    confidence_threshold: float | None = 0.5

class PlaybookExecuteRequest(BaseModel):
    playbook_id: str
    params: Dict[str, Any] | None = None

def _playbook_store_path() -> Path:
    return Path(os.getenv('GENERATED_PLAYBOOK_STORE_PATH', 'data/playbooks/generated_playbooks.json'))


def _load_generated_playbooks() -> Dict[str, Dict[str, Any]]:
    path = _playbook_store_path()
    try:
        if not path.exists():
            return {}
        data = json.loads(path.read_text(encoding='utf-8'))
        if isinstance(data, dict):
            return {str(k): v for k, v in data.items() if isinstance(v, dict)}
    except Exception:
        pass
    return {}


def _save_generated_playbooks(store: Dict[str, Dict[str, Any]]) -> None:
    path = _playbook_store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2, sort_keys=True), encoding='utf-8')


_PLAYBOOK_STORE: Dict[str, Dict[str, Any]] = _load_generated_playbooks()

@router_playbooks.post('/generate')
async def generate_playbook(payload: PlaybookRequest):
    # Minimal validation
    if not payload.graph and not payload.session_ids:
        raise HTTPException(status_code=400, detail='graph_or_session_ids_required')
    # If graph provided, enrich with taxonomies
    graph = payload.graph or {'nodes': [], 'edges': []}
    graph = enrich_graph_with_taxonomies(graph, {'mitre_techniques': payload.mitre_techniques})
    # Prefer declarative templates in playbooks/templates
    templates_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), '..', 'playbooks', 'templates')
    templates_dir = os.path.normpath(templates_dir)
    steps = []
    selected_template = None
    try:
        tactics = graph.get('taxonomies', {})
        memory_required = _graph_requires_memory(graph, payload.mitre_techniques or [])
        if memory_required:
            preferred = 'forensics_memory.yml'
        elif tactics.get('cvss_base', 0) >= 7 or tactics.get('dread_score', 0) >= 3 or 'Repudiation' in tactics.get('stride', []):
            preferred = 'containment_forensics.json'
        else:
            preferred = 'monitor_notify.json'
        pref_path = Path(templates_dir) / preferred
        if pref_path.exists():
            template_data = _load_template_file(pref_path)
            if template_data:
                selected_template = template_data
                steps = template_data.get('steps', [])
    except Exception:
        # fallback to inlined rules
        selected_template = None
    if not steps:
        tactics = graph.get('taxonomies', {})
        if tactics.get('cvss_base', 0) >= 7 or tactics.get('dread_score', 0) >= 3 or 'Repudiation' in tactics.get('stride', []):
            steps = [{'action': 'isolate_hosts', 'desc': 'Isolate affected hosts from network', 'type': 'containment'},
                     {'action': 'collect_evidence', 'desc': 'Collect memory/process dumps and file samples', 'type': 'forensics'}]
        else:
            steps = [{'action': 'monitor', 'desc': 'Increase monitoring and alerting for correlated entities', 'type': 'monitoring'},
                     {'action': 'notify', 'desc': 'Notify security team with summary', 'type': 'notification'}]

    metadata = graph.get('metadata') if isinstance(graph.get('metadata'), dict) else {}
    corroboration_count = int(metadata.get('corroboration_count') or 0)
    approval_state = metadata.get('approval_state') or {}
    missing_evidence = list(metadata.get('missing_evidence') or [])
    confirmed_evidence = list(metadata.get('confirmed_evidence') or [])
    recommendation_actions = list(metadata.get('recommendation_actions') or [])
    evidence_summary = metadata.get('evidence_summary') if isinstance(metadata.get('evidence_summary'), dict) else {}
    corroboration_summary = metadata.get('corroboration_summary') if isinstance(metadata.get('corroboration_summary'), dict) else {}
    confidence_threshold = float(payload.confidence_threshold or 0.5)
    evidence_labels = " ".join(str(item.get('finding') or '') for item in confirmed_evidence if isinstance(item, dict)).lower()
    action_labels = " ".join(str(action.get('primary_action') or '') for action in recommendation_actions if isinstance(action, dict)).lower()
    missing_labels = " ".join(str(item) for item in missing_evidence).lower()
    email_fraud_case = any(
        token in f"{evidence_labels} {action_labels} {missing_labels}"
        for token in ('supplier', 'email', 'macro', 'attachment', 'pdf attachment', 'vendor', 'mailbox_trace', 'click_telemetry')
    )
    guardrails = {
        'confidence_threshold': confidence_threshold,
        'corroborating_domain_count': corroboration_count,
        'approval_state': approval_state.get('status') or ('pending' if approval_state.get('required') else 'not_required'),
        'missing_evidence': missing_evidence[:8],
        'eligible_for_response': bool(
            confidence_threshold >= 0.62
            and corroboration_count >= 2
            and (approval_state.get('status') in {'approved', 'not_required'} or (not approval_state.get('required') and not approval_state.get('status')))
            and not missing_evidence
        ),
    }
    for step in steps:
        if isinstance(step, dict):
            step.setdefault('guardrails', guardrails)
            step_type = str(step.get('type') or step.get('action') or '').lower()
            if ('contain' in step_type or 'isolate' in step_type) and not guardrails['eligible_for_response']:
                step['blocked'] = True
                step['blocked_reason'] = 'containment_requires_corroboration_and_missing_evidence_clearance'
                step['required_evidence'] = guardrails['missing_evidence'][:4]

    pb_id = f'pb-{uuid.uuid4().hex[:8]}'
    playbook = {
        'id': pb_id,
        'created': time.time(),
        'confidence_threshold': float(payload.confidence_threshold or 0.5),
        'graph_summary': {
            'nodes': len(graph.get('nodes', [])),
            'edges': len(graph.get('edges', []))
        },
        'guardrails': guardrails,
        'confirmed_evidence': confirmed_evidence[:6],
        'missing_evidence': missing_evidence[:8],
        'priority_next_pulls': [str(action.get('primary_action')) for action in recommendation_actions[:5] if isinstance(action, dict) and action.get('primary_action')],
        'evidence_summary': {
            'plain_language': evidence_summary.get('plain_language'),
            'drilldown': evidence_summary.get('drilldown'),
            'corroboration_summary': corroboration_summary,
        },
        'containment_preconditions': [
            'confidence threshold met',
            'independent corroboration threshold met',
            'human approval complete when required',
            'missing evidence checklist cleared',
        ],
        'handoff_by_role': {
            'leadership': [
                'Review business impact and whether access should be frozen.' if not email_fraud_case else 'Freeze any supplier payment or bank-detail changes linked to the message until verification completes.',
                'Confirm whether legal, compliance, or customer communications may be needed.' if not email_fraud_case else 'Confirm whether finance, legal, or supplier-management stakeholders must be informed before any funds move.',
            ],
            'soc_analyst': [
                'Validate the confirmed evidence and collect the missing records listed above.',
                'Escalate immediately if privileged access, secret reads, or cloud-native detections are confirmed.' if not email_fraud_case else 'Escalate immediately if supplier-baseline drift, mailbox delivery, click telemetry, or malicious detonation results are confirmed.',
            ],
            'threat_hunter': [
                'Pivot across related identities, IPs, and resources for adjacent attack activity.',
                'Widen the search window around the detected chain to find earlier access or later impact.' if not email_fraud_case else 'Search for the same sender domains, links, hashes, and follow-on identity or endpoint pivots elsewhere in the tenant/account.',
            ],
            'forensics': [
                'Preserve timeline, policy change history, secret-access history, and native incident snapshots.' if not email_fraud_case else 'Preserve the message, raw headers, mailbox trace, click telemetry, attachment artifacts, and supplier baseline history.',
                'Delay destructive containment until preservation steps are complete.',
            ],
        },
        'taxonomies': graph.get('taxonomies', {}),
        'template': selected_template.get('id') if selected_template else None,
        'steps': steps
    }
    _PLAYBOOK_STORE[pb_id] = playbook
    _save_generated_playbooks(_PLAYBOOK_STORE)
    return {'playbook_id': pb_id, 'playbook': playbook}

@router_playbooks.post('/execute', operation_id='playbooks_execute')
async def execute_playbook(payload: PlaybookExecuteRequest):
    global _PLAYBOOK_STORE
    if payload.playbook_id not in _PLAYBOOK_STORE:
        _PLAYBOOK_STORE = _load_generated_playbooks()
    pb = _PLAYBOOK_STORE.get(payload.playbook_id)
    if not pb:
        raise HTTPException(status_code=404, detail='playbook_not_found')
    # Dispatch asynchronously to playbook worker (EVENT_QUEUE-backed if present)
    context = {'playbook_id': pb['id'], 'issued_at': time.time()}
    res = await dispatch_playbook(pb, context)
    execution = {'playbook_id': pb['id']}
    execution.update(res or {})
    return {'execution': execution}

# Export a single combined router so importing modules (like src.api.app)
# receive all playbook-related endpoints regardless of which internal
# sub-router they target. This avoids accidental 404s when the module
# is imported and a specific `router` symbol is expected.
router = APIRouter()
try:
    router.include_router(router_playbook_single)
except Exception:
    pass
try:
    router.include_router(router_playbook_root)
except Exception:
    pass
try:
    router.include_router(router_playbooks)
except Exception:
    pass

__all__ = ['router']
