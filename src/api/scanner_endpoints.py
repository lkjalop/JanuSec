from __future__ import annotations
from fastapi import APIRouter, Request, HTTPException
from typing import Dict, Any
import os

router = APIRouter(prefix='/api/v1/scanners', tags=['scanners'])


def _require_api_key(request: Request) -> None:
    hdr = request.headers.get('x-api-key') or request.headers.get('X-API-Key')
    dev_ok = os.getenv('ALLOW_DEV_API_KEY','1').lower() in {'1','true','yes'}
    if not hdr and not dev_ok:
        raise HTTPException(status_code=403, detail='api_key_required')


# Minimal placeholder health/trigger endpoints for Trivy and Snyk
@router.get('/trivy/health')
async def trivy_health(request: Request) -> Dict[str, Any]:
    _require_api_key(request)
    return {'status': 'ok', 'name': 'trivy', 'last_scan': None}


@router.post('/trivy/trigger')
async def trivy_trigger(payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    _require_api_key(request)
    image = (payload.get('image') or payload.get('target'))
    if not image:
        raise HTTPException(status_code=400, detail='image_required')
    try:
        from src.collectors.scanners.trivy_connector import TrivyConnector  # type: ignore
    except Exception:
        raise HTTPException(status_code=503, detail='trivy_unavailable')
    conn = TrivyConnector()
    sbom = await conn.run_scan(image)
    res = await conn.forward_to_sbom(sbom)
    return {'status': 'scheduled', 'target': image, 'sbom_result': res}


@router.get('/snyk/health')
async def snyk_health(request: Request) -> Dict[str, Any]:
    _require_api_key(request)
    return {'status': 'ok', 'name': 'snyk', 'last_scan': None}


@router.post('/snyk/trigger')
async def snyk_trigger(payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    _require_api_key(request)
    project = (payload.get('project') or payload.get('target'))
    if not project:
        raise HTTPException(status_code=400, detail='project_required')
    try:
        from src.collectors.scanners.snyk_connector import SnykConnector  # type: ignore
    except Exception:
        raise HTTPException(status_code=503, detail='snyk_unavailable')
    conn = SnykConnector()
    sbom = await conn.run_scan(project)
    res = await conn.forward_to_sbom(sbom)
    return {'status': 'scheduled', 'target': project, 'sbom_result': res}


@router.get('/syft/health')
async def syft_health(request: Request) -> Dict[str, Any]:
    _require_api_key(request)
    try:
        from src.collectors.scanners.syft_connector import SyftConnector  # type: ignore
        conn = SyftConnector()
        return {'status': 'ok', **conn.health_snapshot()}
    except Exception:
        return {'status': 'degraded', 'name': 'syft'}


@router.post('/syft/trigger')
async def syft_trigger(payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    """Run Syft SBOM scan and forward to SBOM upload.

    Body: { target: string }
    """
    _require_api_key(request)
    target = (payload.get('target') or payload.get('image') or payload.get('path'))
    if not target:
        raise HTTPException(status_code=400, detail='target_required')
    try:
        from src.collectors.scanners.syft_connector import SyftConnector  # type: ignore
    except Exception:
        raise HTTPException(status_code=503, detail='syft_unavailable')
    conn = SyftConnector()
    sbom = await conn.run_scan(target)
    # Auto-forward SBOM to upload endpoint (prefer in-app forwarding for tests)
    api_key_hdr = request.headers.get('x-api-key') or os.getenv('API_KEY')
    if not api_key_hdr:
        raise HTTPException(status_code=403, detail='api_key_required')
    # Internal forward: construct a Starlette Request and call the handler directly
    try:
        from starlette.requests import Request as _Request
        import json as _json
        async def _recv():
            return {'type': 'http.request', 'body': _json.dumps(sbom).encode('utf-8'), 'more_body': False}
        scope = {
            'type': 'http',
            'scheme': 'http',
            'http_version': '1.1',
            'method': 'POST',
            'path': '/api/v1/sbom/upload',
            'raw_path': b'/api/v1/sbom/upload',
            'query_string': b'',
            'headers': [
                (b'x-api-key', str(api_key_hdr).encode('utf-8')),
                (b'content-type', b'application/json'),
                (b'content-length', str(len(_json.dumps(sbom).encode('utf-8'))).encode('utf-8')),
            ],
            'client': ('testclient', 50000),
            'server': ('testserver', 80),
            'app': request.app,
        }
        req2 = _Request(scope, _recv)
        from src.api.sbom_endpoints import sbom_upload as _sbom_upload  # type: ignore
        res = await _sbom_upload(req2)
    except Exception as e:
        raise HTTPException(status_code=502, detail={'error': 'sbom_forward_failed', 'reason': str(e)})
    # Best-effort HopGraph validation snapshot
    hopgraph_meta: Dict[str, Any] = {}
    try:
        hg = getattr(request.app.state, 'hopgraph', None)
        if hg is None:
            from src.graph.hopgraph import GLOBAL_HOPGRAPH  # type: ignore
            hg = GLOBAL_HOPGRAPH
        hopgraph_meta = {'version': hg.get_version()} if hg else {}
    except Exception:
        hopgraph_meta = {}
    return {'status': 'scheduled', 'target': target, 'sbom_result': res, 'hopgraph': hopgraph_meta}


@router.get('/grype/health')
async def grype_health(request: Request) -> Dict[str, Any]:
    _require_api_key(request)
    try:
        from src.collectors.scanners.grype_connector import GrypeConnector  # type: ignore
        conn = GrypeConnector()
        return {'status': 'ok', **conn.health_snapshot()}
    except Exception:
        return {'status': 'degraded', 'name': 'grype'}


@router.post('/grype/trigger')
async def grype_trigger(payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    """Run Grype vulnerability scan and forward components to SBOM upload.

    Body: { target: string }
    """
    _require_api_key(request)
    target = (payload.get('target') or payload.get('image') or payload.get('path'))
    if not target:
        raise HTTPException(status_code=400, detail='target_required')
    try:
        from src.collectors.scanners.grype_connector import GrypeConnector  # type: ignore
    except Exception:
        raise HTTPException(status_code=503, detail='grype_unavailable')
    conn = GrypeConnector()
    sbom = await conn.run_scan(target)
    # Auto-forward SBOM to upload endpoint (prefer in-app forwarding for tests)
    api_key_hdr = request.headers.get('x-api-key') or os.getenv('API_KEY')
    if not api_key_hdr:
        raise HTTPException(status_code=403, detail='api_key_required')
    try:
        from starlette.requests import Request as _Request
        import json as _json
        async def _recv():
            return {'type': 'http.request', 'body': _json.dumps(sbom).encode('utf-8'), 'more_body': False}
        scope = {
            'type': 'http',
            'scheme': 'http',
            'http_version': '1.1',
            'method': 'POST',
            'path': '/api/v1/sbom/upload',
            'raw_path': b'/api/v1/sbom/upload',
            'query_string': b'',
            'headers': [
                (b'x-api-key', str(api_key_hdr).encode('utf-8')),
                (b'content-type', b'application/json'),
                (b'content-length', str(len(_json.dumps(sbom).encode('utf-8'))).encode('utf-8')),
            ],
            'client': ('testclient', 50000),
            'server': ('testserver', 80),
            'app': request.app,
        }
        req2 = _Request(scope, _recv)
        from src.api.sbom_endpoints import sbom_upload as _sbom_upload  # type: ignore
        res = await _sbom_upload(req2)
    except Exception as e:
        raise HTTPException(status_code=502, detail={'error': 'sbom_forward_failed', 'reason': str(e)})
    hopgraph_meta: Dict[str, Any] = {}
    try:
        hg = getattr(request.app.state, 'hopgraph', None)
        if hg is None:
            from src.graph.hopgraph import GLOBAL_HOPGRAPH  # type: ignore
            hg = GLOBAL_HOPGRAPH
        hopgraph_meta = {'version': hg.get_version()} if hg else {}
    except Exception:
        hopgraph_meta = {}
    return {'status': 'scheduled', 'target': target, 'sbom_result': res, 'hopgraph': hopgraph_meta}


__all__ = ['router']
