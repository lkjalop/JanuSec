from __future__ import annotations

from fastapi import APIRouter, Body, HTTPException
from typing import Any, Dict, List
import json, os, time

from src.soar.playbook_loader import resolve_for_factor, extract_context_from_event, render_playbook
from src.core.threat_modeling.factor_taxonomy import _FACTOR_MAP
from src.core.factor_mapper import score_candidates_from_event
from typing import Tuple
import os

router = APIRouter(prefix='/api/v1/playbooks', tags=['Playbooks'])

# Lightweight library loader (independent of factor-based playbook resolution above)
_LIB_PATH = os.getenv('PLAYBOOK_LIBRARY_PATH', 'data/playbooks.json')
_LIB_CACHE: List[Dict[str, Any]] = []
_LIB_MTIME: float = 0.0
_LIB_LAST_LOAD: float = 0.0
_LIB_CACHE_SECONDS = 30.0

def _load_library(force: bool = False) -> List[Dict[str, Any]]:
    global _LIB_CACHE, _LIB_MTIME, _LIB_LAST_LOAD
    now = time.time()
    if force or not _LIB_CACHE or (now - _LIB_LAST_LOAD) > _LIB_CACHE_SECONDS:
        try:
            st = os.stat(_LIB_PATH)
            if force or st.st_mtime != _LIB_MTIME:
                with open(_LIB_PATH, 'r', encoding='utf-8') as fh:
                    data = json.load(fh)
                if isinstance(data, list):
                    _LIB_CACHE = [d for d in data if isinstance(d, dict)]
                    _LIB_MTIME = st.st_mtime
            _LIB_LAST_LOAD = now
        except Exception:
            _LIB_CACHE = []
            _LIB_LAST_LOAD = now
    return _LIB_CACHE

@router.get('/library')
def list_library() -> Dict[str, Any]:
    return {'playbooks': _load_library(), 'count': len(_LIB_CACHE), 'mtime': _LIB_MTIME}

@router.get('/recommend')
def recommend_playbooks(factors: str | None = None, limit: int = 5) -> Dict[str, Any]:
    flist: List[str] = []
    if factors:
        flist = [f.strip() for f in factors.split(',') if f.strip()]
    books = _load_library()
    scored: List[Dict[str, Any]] = []
    def _score_playbook(pb: Dict[str, Any], fset: set) -> Tuple[float, Dict[str, Any]]:
        score = 0.0
        matched = {'any': [], 'all': [], 'none': []}
        # support nested lists or single values
        any_list = pb.get('match_any') or []
        all_list = pb.get('match_all') or []
        none_list = pb.get('match_none') or []

        any_set = set(any_list)
        all_set = set(all_list)
        none_set = set(none_list)

        any_hits = sorted(list(any_set.intersection(fset)))
        all_hits = sorted(list(all_set.intersection(fset)))
        none_hits = sorted(list(none_set.intersection(fset)))

        matched['any'] = any_hits
        matched['all'] = all_hits
        matched['none'] = none_hits

        # scoring heuristics (tunable)
        if any_hits:
            score += 0.15 * len(any_hits)
        if all_list:
            # reward when all required factors present, penalize if missing
            if all_set.issubset(fset):
                score += 0.5 + 0.08 * len(all_set)
            else:
                # missing required factors: negative score to deprioritize
                missing = len(all_set - fset)
                score -= 0.25 * missing
        if none_hits:
            # presence of forbidden factors reduces score significantly
            score -= 0.4 * len(none_hits)

        # optional weight per playbook
        weight = float(pb.get('weight') or 1.0)
        score *= weight

        # heuristic boost for multi-domain/high-quality mappings
        if 'multi_source_correlation' in fset and 'mapping_semantics_rich' in fset:
            score += 0.22

        return score, matched

    fset = set(flist)
    for pb in books:
        score, matched = _score_playbook(pb, fset)
        if score > 0:
            scored.append({
                'id': pb.get('id'), 'title': pb.get('title'), 'score': round(score,3),
                'actions': pb.get('actions'), 'roles': pb.get('roles'), 'sla_minutes': pb.get('sla_minutes'),
                'matched_any': matched.get('any'), 'matched_all': matched.get('all'), 'matched_none': matched.get('none')
            })
    scored.sort(key=lambda x: x.get('score') or 0.0, reverse=True)
    return {'recommendations': scored[:max(1, min(limit, 20))], 'input_factors': flist}


@router.post('/resolve')
def resolve_playbooks(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """Resolve playbooks for a factor or for an event (factor inferred).

    Payload options:
      {"factor":"identity:..."}
      or {"event": {...}, "factor": "..."}
    """
    factor = payload.get('factor')
    event = payload.get('event')
    tenant = payload.get('tenant') or os.getenv('DEFAULT_TENANT')

    # Simple per-tenant toggle: allow execution only if tenant is in allowed list
    allowed = os.getenv('PLAYBOOK_TENANT_ALLOW')
    if allowed:
        allowed_set = {x.strip() for x in allowed.split(',') if x.strip()}
        if tenant and tenant not in allowed_set:
            return {'error': 'playbooks_disabled_for_tenant', 'resolved': []}

    if not factor and event:
        ranked = score_candidates_from_event(event)
        candidate_info = [{'factor': r[0], 'score': r[1]} for r in ranked[:5]]
        factor = candidate_info[0]['factor'] if candidate_info else None
    pbs = resolve_for_factor(factor) if factor else []
    out: List[Dict[str, Any]] = []
    ctx = extract_context_from_event(event or {})
    for pb in pbs:
        out.append({'name': pb.get('name'), 'rendered': render_playbook(pb, ctx)})
    resp: Dict[str, Any] = {'resolved': out}
    if 'candidate_info' in locals():
        resp['candidates'] = candidate_info
    return resp



@router.post('/candidates')
def preview_candidates(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """Return ranked factor candidates for an event (no rendering).

    Payload: {"event": {...}}
    """
    event = payload.get('event') or {}
    ranked = score_candidates_from_event(event)
    return {'candidates': [{'factor': f, 'score': s} for f, s in ranked[:10]]}


@router.post('/render_candidates')
def render_top_candidates(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """Return rendered playbooks for the top-N candidate factors.

    Payload: {"event": {...}, "top_n": 3}
    """
    event = payload.get('event') or {}
    top_n = int(payload.get('top_n') or 3)
    ranked = score_candidates_from_event(event)
    candidates = [f for f, _ in ranked[:top_n]]
    ctx = extract_context_from_event(event)
    out = []
    for fac in candidates:
        pbs = resolve_for_factor(fac)
        for pb in pbs:
            out.append({'factor': fac, 'name': pb.get('name'), 'rendered': render_playbook(pb, ctx)})
    return {'rendered': out}


__all__ = ['router']
