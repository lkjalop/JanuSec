from __future__ import annotations

from fastapi import APIRouter, HTTPException, Body, Header, Request
from typing import Dict, Any
import os
import yaml
from src.graph.cooccurrence import get_suppression_templates, reload_config

router = APIRouter(prefix='/api/v1/admin/suppression', tags=['Suppression Admin'])

def _admin_ok(x_admin_key: str | None) -> bool:
    expected = os.getenv('ADMIN_API_KEY')
    return bool(expected) and x_admin_key == expected

try:
    from src.api.server import audit_emit, audit_user  # type: ignore
except Exception:
    audit_emit = None
    audit_user = None


@router.get('/')
async def list_suppression(request: Request, x_admin_key: str | None = Header(None)) -> Dict[str, Any]:
    if not _admin_ok(x_admin_key):
        raise HTTPException(status_code=403, detail='forbidden')
    try:
        tmpl = get_suppression_templates()
        if audit_emit:
            try: audit_emit('suppression_list', audit_user(request, None), {'count': len(tmpl)})
            except Exception: pass
        return {'suppression_templates': {','.join(k): v for k,v in tmpl.items()}}
    except Exception:
        raise HTTPException(status_code=500, detail='failed_to_read_templates')


@router.post('/reload')
async def reload_suppression(request: Request, path: str | None = Body(None, embed=True), x_admin_key: str | None = Header(None)) -> Dict[str, Any]:
    if not _admin_ok(x_admin_key):
        raise HTTPException(status_code=403, detail='forbidden')
    try:
        reload_config(path)
        if audit_emit:
            try: audit_emit('suppression_reload', audit_user(request, None), {'path': path})
            except Exception: pass
        return {'ok': True}
    except Exception:
        raise HTTPException(status_code=500, detail='reload_failed')


@router.post('/set')
async def set_suppression(request: Request, payload: Dict[str, float] = Body(...), x_admin_key: str | None = Header(None)) -> Dict[str, Any]:
    if not _admin_ok(x_admin_key):
        raise HTTPException(status_code=403, detail='forbidden')
    try:
        path = 'config/cooccurrence.yaml'
        doc = {}
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as fh:
                    doc = yaml.safe_load(fh) or {}
            except Exception:
                doc = {}
        sup = doc.get('suppression_templates') or {}
        for k,v in payload.items():
            sup[str(k)] = float(v)
        doc['suppression_templates'] = sup
        with open(path, 'w', encoding='utf-8') as fh:
            yaml.safe_dump(doc, fh)
        reload_config(path)
        if audit_emit:
            try: audit_emit('suppression_set', audit_user(request, None), {'changed': list(payload.keys())})
            except Exception: pass
        return {'ok': True}
    except Exception:
        raise HTTPException(status_code=500, detail='write_failed')


__all__ = ['router']