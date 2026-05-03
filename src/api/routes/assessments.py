"""routes/assessments.py — Lightweight assessment action endpoints.

Extracted from app.py to keep the main module smaller and these routes
independently testable. Handles:
  POST /api/v1/reports/{report_id}/ask_for_logs
  POST /api/v1/assessments/generate_persona
  POST /api/v1/assessments/hopgraph_report
"""
from __future__ import annotations

import json as _json
import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix='/api/v1', tags=['assessments'])


@router.post('/reports/{report_id}/ask_for_logs')
async def ask_for_logs(report_id: str, req: Request):
    try:
        payload = await req.json()
    except Exception:
        payload = {}
    recipient = (payload.get('recipient') or payload.get('email') or 'security@example.com')
    reason = payload.get('reason') or 'Please provide forensic logs and timeline for further triage.'
    message = {
        'to': recipient,
        'subject': f"Request for additional logs: report {report_id}",
        'body': (
            f"Hello,\n\nWe are investigating report {report_id}. "
            "Please provide the following logs and context:\n"
            "- Mail server logs (timestamps +/- 15m)\n"
            "- Web proxy logs for linked URLs\n"
            "- Endpoint telemetry for recipient hosts\n\n"
            f"Reason: {reason}\n\nThanks,\nSecurity Team"
        ),
    }
    return JSONResponse({'ok': True, 'message': message})


@router.post('/assessments/generate_persona')
async def generate_persona(req: Request):
    try:
        payload = await req.json()
    except Exception:
        payload = {}
    assessment_id = payload.get('assessment_id')
    if not assessment_id:
        return JSONResponse({'detail': 'missing_assessment_id'}, status_code=400)
    row_index = int(payload.get('row_index') or 0)
    persona = (payload.get('persona') or 'soc').strip()

    # best-effort: find REPORT_STORE on deep_analyze router module
    report = None
    try:
        from src.api import deep_analyze_endpoints as dae  # noqa: PLC0415
        report = getattr(dae, 'REPORT_STORE', {}).get(assessment_id)
    except Exception:
        pass
    if not report:
        return JSONResponse({'detail': 'report_not_found'}, status_code=404)

    rows = report.get('per_row') or report.get('rows') or []
    if isinstance(rows, dict):
        rows = list(rows.values())
    if row_index < 0 or row_index >= len(rows):
        return JSONResponse({'detail': 'invalid_row_index'}, status_code=400)
    incident = rows[row_index]

    # Try cached_generate first, else fall back to DEFAULT_CLIENT.generate
    resp: dict | None = None
    try:
        from src.reporting.llm_helper import cached_generate  # noqa: PLC0415
        resp = cached_generate(persona, incident)
    except Exception:
        try:
            from src.integrations.llm_client import DEFAULT_CLIENT  # noqa: PLC0415
            prompt = incident.get('summary') or incident.get('text') or _json.dumps(incident)
            gen = DEFAULT_CLIENT.generate(prompt)
            resp = {'text': gen['text']} if (isinstance(gen, dict) and 'text' in gen) else {'text': str(gen)}
        except Exception:
            return JSONResponse({'detail': 'llm_unavailable'}, status_code=500)

    # Persist persona report back into REPORT_STORE when possible
    try:
        llm_rows = report.get('llm_rows')
        if isinstance(llm_rows, list) and len(llm_rows) > row_index:
            target_row = llm_rows[row_index]
        else:
            raw_rows = report.get('per_row') or report.get('rows') or {}
            if isinstance(raw_rows, dict):
                vals = list(raw_rows.values())
                target_row = vals[row_index] if row_index < len(vals) else None
            elif isinstance(raw_rows, list):
                target_row = raw_rows[row_index] if row_index < len(raw_rows) else None
            else:
                target_row = None
        if target_row is not None:
            pr = target_row.get('persona_reports') or {}
            pr[persona] = resp
            target_row['persona_reports'] = pr
    except Exception as exc:
        logger.debug('generate_persona: persist failed: %s', exc)

    # Auto-routing hook when available
    try:
        from src.api.deep_analyze_endpoints import _auto_route_incident  # noqa: PLC0415
        text = resp.get('text') if isinstance(resp, dict) else str(resp)
        _auto_route_incident(target=None, persona=persona, text=text, assessment=report)
    except Exception as exc:
        logger.debug('generate_persona: auto_route failed: %s', exc)

    return JSONResponse({'ok': True, 'persona': persona, 'response': resp})


@router.post('/assessments/hopgraph_report')
async def hopgraph_report(req: Request):
    try:
        payload = await req.json()
    except Exception:
        payload = {}
    try:
        from src.api.deep_analyze_endpoints import ingest_hopgraph_report  # noqa: PLC0415
        try:
            return await ingest_hopgraph_report(payload)
        except TypeError:
            return ingest_hopgraph_report(payload)
    except Exception:
        return JSONResponse({'detail': 'deep_analyze_unavailable'}, status_code=503)
