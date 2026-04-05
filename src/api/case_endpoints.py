from __future__ import annotations
"""Case & Artifact endpoints providing a lightweight investigation record with hash-chained artifacts.

Data Model (in-memory + append-only JSONL persistence):
  Case: { id, title, created_ts, updated_ts, status, severity, tenant_id, artifacts:[artifact_id,...], head_hash }
  Artifact: { id, case_id, kind, created_ts, author?, summary?, payload (opaque dict), sha256, prev_hash, chain_hash }

Hash Chain:
  chain_hash = sha256( prev_hash || sha256(payload_json) )
  head_hash for case = chain_hash of most recent artifact

Environment Flags:
  CASE_STORE_PATH (default data/cases.jsonl)
  CASE_ARTIFACT_PATH (default data/case_artifacts.jsonl)

NOTE: This is intentionally lightweight and not a full evidentiary store.
"""
import os, json, time, hashlib, uuid
from pathlib import Path
from typing import Any
from fastapi import APIRouter, HTTPException, Request
from src.api.tenant_helpers import resolve_tenant_id

router = APIRouter(tags=["Cases"])

CASE_PATH = Path(os.getenv('CASE_STORE_PATH', 'data/cases.jsonl'))
ARTIFACT_PATH = Path(os.getenv('CASE_ARTIFACT_PATH', 'data/case_artifacts.jsonl'))

_CASES: dict[str, dict[str, Any]] = {}
_ARTIFACTS: dict[str, dict[str, Any]] = {}
_CASE_ARTS: dict[str, list[str]] = {}

def _ensure_dirs():
    for p in (CASE_PATH, ARTIFACT_PATH):
        try: p.parent.mkdir(parents=True, exist_ok=True)
        except Exception: pass

def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def _chain_hash(prev_hash: str, payload_obj: Any) -> str:
    try:
        payload_bytes = json.dumps(payload_obj, sort_keys=True, separators=(',',':')).encode('utf-8')
    except Exception:
        payload_bytes = b'{}'
    return _sha256_bytes((prev_hash or '').encode('utf-8') + _sha256_bytes(payload_bytes).encode('utf-8'))

def _persist_case(rec: dict[str, Any]):
    _ensure_dirs()
    try:
        with CASE_PATH.open('a', encoding='utf-8') as f:
            f.write(json.dumps(rec) + '\n')
    except Exception:
        pass

def _persist_art(art: dict[str, Any]):
    _ensure_dirs()
    try:
        with ARTIFACT_PATH.open('a', encoding='utf-8') as f:
            f.write(json.dumps(art) + '\n')
    except Exception:
        pass

def _load():
    for path, target, is_art in ((CASE_PATH, _CASES, False), (ARTIFACT_PATH, _ARTIFACTS, True)):
        if not path.exists():
            continue
        try:
            with path.open('r', encoding='utf-8') as f:
                for line in f:
                    line=line.strip()
                    if not line: continue
                    try:
                        rec=json.loads(line)
                        if is_art:
                            _ARTIFACTS[rec.get('id')] = rec
                            cid = rec.get('case_id')
                            if cid:
                                _CASE_ARTS.setdefault(cid, []).append(rec.get('id'))
                        else:
                            _CASES[rec.get('id')] = rec
                    except Exception:
                        continue
        except Exception:
            pass
    # Rebuild head_hash for each case
    for cid, case in _CASES.items():
        arts = [_ARTIFACTS[aid] for aid in _CASE_ARTS.get(cid, []) if aid in _ARTIFACTS]
        arts = sorted(arts, key=lambda a: a.get('created_ts',0))
        head = arts[-1]['chain_hash'] if arts else None
        case['head_hash'] = head

try:
    _load()
except Exception:
    pass

@router.post('/api/v1/cases')
async def create_case(request: Request) -> dict[str, Any]:
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail='bad_json')
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail='bad_json')
    cid = data.get('id') or str(uuid.uuid4())
    now = time.time()
    tenant_id = resolve_tenant_id(request, data.get('tenant_id'))
    rec = {
        'id': cid,
        'title': (data.get('title') or f'Case {cid}')[:160],
        'created_ts': now,
        'updated_ts': now,
        'status': data.get('status') or 'open',
        'severity': data.get('severity') or 'medium',
        'tenant_id': tenant_id,
        'artifacts': [],
        'head_hash': None,
    }
    _CASES[cid] = rec
    _persist_case(rec)
    return {'case': rec}

@router.get('/api/v1/cases')
async def list_cases(limit: int = 100, tenant_id: str | None = None, request: Request = None) -> dict[str, Any]:
    tenant_id = resolve_tenant_id(request, tenant_id)
    rows = list(_CASES.values())
    if tenant_id:
        rows = [c for c in rows if c.get('tenant_id') == tenant_id]
    rows.sort(key=lambda r: r.get('updated_ts',0), reverse=True)
    return {'cases': rows[:limit], 'count': len(rows[:limit])}

@router.get('/api/v1/cases/{case_id}')
async def get_case(case_id: str) -> dict[str, Any]:
    rec = _CASES.get(case_id)
    if not rec:
        raise HTTPException(status_code=404, detail='not_found')
    arts = [_ARTIFACTS[aid] for aid in _CASE_ARTS.get(case_id, []) if aid in _ARTIFACTS]
    return {'case': rec, 'artifacts': arts}

@router.post('/api/v1/cases/{case_id}/artifact')
async def add_artifact(case_id: str, request: Request) -> dict[str, Any]:
    case = _CASES.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail='case_not_found')
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail='bad_json')
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail='bad_json')
    payload = data.get('payload') or {}
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail='bad_payload')
    prev_hash = case.get('head_hash') or ''
    art_id = data.get('id') or str(uuid.uuid4())
    now = time.time()
    chain_hash = _chain_hash(prev_hash, payload)
    art = {
        'id': art_id,
        'case_id': case_id,
        'kind': (data.get('kind') or 'generic')[:64],
        'created_ts': now,
        'author': data.get('author'),
        'summary': (data.get('summary') or '')[:300],
        'payload': payload,
        'prev_hash': prev_hash or None,
        'chain_hash': chain_hash,
        'sha256': _sha256_bytes(json.dumps(payload, sort_keys=True, separators=(',',':')).encode('utf-8')),
    }
    _ARTIFACTS[art_id] = art
    _CASE_ARTS.setdefault(case_id, []).append(art_id)
    case['artifacts'].append(art_id)
    case['head_hash'] = chain_hash
    case['updated_ts'] = now
    _persist_art(art)
    _persist_case(case)
    return {'artifact': art, 'case_head_hash': chain_hash}

@router.get('/api/v1/cases/{case_id}/verify')
async def verify_case_chain(case_id: str) -> dict[str, Any]:
    case = _CASES.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail='case_not_found')
    arts = [_ARTIFACTS[aid] for aid in _CASE_ARTS.get(case_id, []) if aid in _ARTIFACTS]
    arts = sorted(arts, key=lambda a: a.get('created_ts',0))
    prev = ''
    ok = True
    for a in arts:
        recomputed = _chain_hash(prev, a.get('payload'))
        if recomputed != a.get('chain_hash'):
            ok = False
            break
        prev = a.get('chain_hash') or ''
    return {'case_id': case_id, 'verified': ok, 'artifact_count': len(arts), 'head_hash': case.get('head_hash')}

@router.get('/api/v1/cases/metrics')
async def cases_metrics() -> dict[str, Any]:
    """Aggregate lightweight metrics for Evidence Metrics Panel.

    Returns:
      total_cases: total number of cases
      total_artifacts: total artifacts across all cases
      recent_cases_24h: cases created or updated in last 24h
      recent_artifacts_24h: artifacts created in last 24h
      case_severity_distribution: counts by case.severity
      integrity: { cases_with_artifacts, verified_pass, verified_fail, percent_verified }
      failed_cases: (up to 50 case ids) whose chain failed verification
    """
    now = time.time()
    cutoff = now - 86400
    total_cases = len(_CASES)
    total_artifacts = len(_ARTIFACTS)
    recent_cases_24h = sum(1 for c in _CASES.values() if (c.get('updated_ts') or 0) >= cutoff)
    recent_artifacts_24h = sum(1 for a in _ARTIFACTS.values() if (a.get('created_ts') or 0) >= cutoff)
    sev_dist: dict[str,int] = {}
    for c in _CASES.values():
        sev = c.get('severity') or 'unknown'
        sev_dist[sev] = sev_dist.get(sev, 0) + 1
    cases_with_artifacts = 0
    verified_pass = 0
    verified_fail = 0
    failed_cases: list[str] = []
    for cid, case in _CASES.items():
        art_ids = _CASE_ARTS.get(cid, [])
        if not art_ids:
            continue
        cases_with_artifacts += 1
        arts = [_ARTIFACTS[aid] for aid in art_ids if aid in _ARTIFACTS]
        arts = sorted(arts, key=lambda a: a.get('created_ts', 0))
        prev = ''
        ok = True
        for a in arts:
            recomputed = _chain_hash(prev, a.get('payload'))
            if recomputed != a.get('chain_hash'):
                ok = False
                break
            prev = a.get('chain_hash') or ''
        if ok:
            verified_pass += 1
        else:
            verified_fail += 1
            if len(failed_cases) < 50:
                failed_cases.append(cid)
    percent_verified = (verified_pass / cases_with_artifacts * 100.0) if cases_with_artifacts else None
    return {
        'total_cases': total_cases,
        'total_artifacts': total_artifacts,
        'recent_cases_24h': recent_cases_24h,
        'recent_artifacts_24h': recent_artifacts_24h,
        'case_severity_distribution': sev_dist,
        'integrity': {
            'cases_with_artifacts': cases_with_artifacts,
            'verified_pass': verified_pass,
            'verified_fail': verified_fail,
            'percent_verified': percent_verified,
        },
        'failed_cases': failed_cases,
        'generated_ts': now,
    }

__all__ = ['router']
