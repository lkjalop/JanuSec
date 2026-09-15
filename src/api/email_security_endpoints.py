from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from typing import Dict, Any
import os
import time
from typing import Tuple

try:
    from src.artifact.vt_queue import VTQueue  # type: ignore
except Exception:
    try:
        from artifact.vt_queue import VTQueue  # type: ignore
    except Exception:
        VTQueue = None  # type: ignore

_VTQ = VTQueue() if (VTQueue is not None) else None

router = APIRouter(prefix="/api/v1/email", tags=["email-security"])

def _require_api_key(request: Request) -> None:
    hdr = request.headers.get('x-api-key') or request.headers.get('X-API-Key')
    dev_ok = os.getenv('ALLOW_DEV_API_KEY','1').lower() in {'1','true','yes'}
    if not hdr and not dev_ok:
        raise HTTPException(status_code=403, detail='api_key_required')

def _parse_headers(raw: str) -> Dict[str, str]:
    out: Dict[str,str] = {}
    for line in raw.splitlines():
        if ':' not in line: continue
        k,v = line.split(':',1)
        out[k.strip().lower()] = v.strip()
    return out

@router.post('/parse')
async def email_parse(request: Request) -> Dict[str, Any]:
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail='bad_json')
    headers_txt = (data.get('headers') or '').strip()
    if not headers_txt:
        raise HTTPException(status_code=400, detail='no_headers')
    hdr = _parse_headers(headers_txt)
    factors: list[str] = []
    spf = hdr.get('received-spf') or hdr.get('spf')
    dmarc = hdr.get('authentication-results') or ''
    if spf and 'pass' not in spf.lower():
        factors.append('email:spf_fail')
    if 'dmarc=fail' in dmarc.lower():
        factors.append('email:dmarc_fail')
    return {'factors': factors, 'count': len(factors)}

@router.post('/security/vt/hash')
async def vt_hash(payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    _require_api_key(request)
    if _VTQ is None or not _VTQ.enabled:
        raise HTTPException(status_code=503, detail='vt_unavailable')
    sha256 = (payload.get('sha256') or '').strip().lower()
    if not sha256:
        raise HTTPException(status_code=400, detail='sha256_required')
    try:
        _VTQ.submit(sha256)
        deadline = time.time() + 1.0
        while time.time() < deadline:
            ready = _VTQ.poll_ready()
            if ready:
                break
            await _yield_once()
    except Exception:
        pass
    res = _VTQ.get(sha256)
    return { 'sha256': sha256, 'result': (res or {'status':'pending'}) }

async def _yield_once():
    try:
        import asyncio
        await asyncio.sleep(0)
    except Exception:
        pass

@router.post('/security/dmarc/enforce')
async def dmarc_enforce(payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    _require_api_key(request)
    headers = payload.get('headers') or {}
    hdrs: Dict[str, str]
    if isinstance(headers, str):
        hdrs = _parse_headers(headers)
    elif isinstance(headers, dict):
        # normalize lower keys
        hdrs = { str(k).strip().lower(): str(v) for k,v in headers.items() }
    else:
        raise HTTPException(status_code=400, detail='headers_required')
    auth = (hdrs.get('authentication-results') or '')
    dmarc = 'pass' if 'dmarc=pass' in auth.lower() else ('fail' if 'dmarc=fail' in auth.lower() else None)
    spf = 'pass' if 'spf=pass' in auth.lower() else ('fail' if 'spf=fail' in auth.lower() else None)
    dkim = 'pass' if 'dkim=pass' in auth.lower() else ('fail' if 'dkim=fail' in auth.lower() else None)
    pol_hdr = hdrs.get('dmarc-policy') or hdrs.get('x-dmarc-policy') or ''
    policy = None
    s = str(pol_hdr).lower()
    if 'reject' in s:
        policy = 'reject'
    elif 'quarantine' in s:
        policy = 'quarantine'
    action = 'none'
    factors: list[str] = []
    if dmarc == 'fail':
        action = policy or 'quarantine'
        factors.append('email:dmarc_fail')
        factors.append('policy:' + ('reject' if action == 'reject' else 'quarantine'))
    if spf == 'fail':
        factors.append('email:spf_fail')
    if dkim == 'fail':
        factors.append('email:dkim_fail')
    return { 'enforcement': action, 'auth': { 'dmarc': dmarc, 'spf': spf, 'dkim': dkim, 'policy': policy }, 'factors': factors }

# Proofpoint TAP health endpoint for LIVE console
try:
    from src.collectors.email.proofpoint_tap_collector import ProofpointTAPCollector  # type: ignore
except Exception:
    ProofpointTAPCollector = None  # type: ignore
try:
    from src.collectors.email.mimecast_collector import MimecastCollector  # type: ignore
except Exception:
    MimecastCollector = None  # type: ignore
try:
    from src.collectors.email.abnormal_collector import AbnormalCollector  # type: ignore
except Exception:
    AbnormalCollector = None  # type: ignore
try:
    from src.collectors.email.defender_collector import DefenderCollector  # type: ignore
except Exception:
    DefenderCollector = None  # type: ignore
try:
    from src.integrations.email_arc_bimi import enforce_arc_bimi  # type: ignore
except Exception:
    enforce_arc_bimi = None  # type: ignore

@router.get('/connectors/proofpoint/health')
async def proofpoint_health(request: Request) -> Dict[str, Any]:
    """Return a lightweight health snapshot from the Proofpoint TAP collector.

    Query params:
      - tenant_id: optional tenant identifier (default 'default').
    """
    _require_api_key(request)
    if ProofpointTAPCollector is None:
        raise HTTPException(status_code=503, detail='proofpoint_unavailable')
    try:
        tenant_id = request.query_params.get('tenant_id') or 'default'
        collector = ProofpointTAPCollector(tenant_id)
        return collector.health_snapshot()
    except Exception:
        raise HTTPException(status_code=500, detail='health_error')

@router.get('/connectors/mimecast/health')
async def mimecast_health(request: Request) -> Dict[str, Any]:
    """Return a lightweight health snapshot from the Mimecast collector."""
    _require_api_key(request)
    if MimecastCollector is None:
        raise HTTPException(status_code=503, detail='mimecast_unavailable')
    try:
        tenant_id = request.query_params.get('tenant_id') or 'default'
        collector = MimecastCollector(tenant_id)
        return collector.health_snapshot()
    except Exception:
        raise HTTPException(status_code=503, detail='mimecast_unavailable')

@router.get('/connectors/abnormal/health')
async def abnormal_health(request: Request) -> Dict[str, Any]:
    """Return a health snapshot from the Abnormal collector."""
    _require_api_key(request)
    if AbnormalCollector is None:
        raise HTTPException(status_code=503, detail='abnormal_unavailable')
    try:
        tenant_id = request.query_params.get('tenant_id') or 'default'
        collector = AbnormalCollector(tenant_id)
        return collector.health_snapshot()
    except Exception:
        raise HTTPException(status_code=500, detail='health_error')

@router.get('/connectors/defender/health')
async def defender_health(request: Request) -> Dict[str, Any]:
    """Return a health snapshot from the Defender collector."""
    _require_api_key(request)
    if DefenderCollector is None:
        raise HTTPException(status_code=503, detail='defender_unavailable')
    try:
        tenant_id = request.query_params.get('tenant_id') or 'default'
        collector = DefenderCollector(tenant_id)
        return collector.health_snapshot()
    except Exception:
        raise HTTPException(status_code=500, detail='health_error')

__all__ = ['router']


@router.post('/security/arc_bimi/enforce')
async def arc_bimi_enforce(payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    _require_api_key(request)
    if enforce_arc_bimi is None:
        raise HTTPException(status_code=503, detail='arc_bimi_unavailable')
    headers = payload.get('headers') or {}
    if isinstance(headers, str):
        hdrs = _parse_headers(headers)
    elif isinstance(headers, dict):
        hdrs = { str(k).strip().lower(): str(v) for k,v in headers.items() }
    else:
        raise HTTPException(status_code=400, detail='headers_required')
    return enforce_arc_bimi(hdrs)
