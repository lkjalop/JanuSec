from fastapi import APIRouter, Request, Query, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, PlainTextResponse
from html import escape
from typing import Any
import json
try:
    from src.reporting.email_summaries import tier1_summary, tier2_summary
except Exception:
    from ..reporting.email_summaries import tier1_summary, tier2_summary
try:
    from src.correlation.chain_builder import ChainBuilder
except Exception:
    ChainBuilder = None  # type: ignore
try:
    from src.connectors.email.click_persistence import fetch_recent_clicks
except Exception:
    fetch_recent_clicks = None  # type: ignore
try:
    # Prefer absolute import when running under normal package layout
    from src.reporting.comprehensive_report_generator import build_report_html
except Exception:
    # Fallback to relative import when package context is different (tests may import `api` as top-level)
    from ..reporting.comprehensive_report_generator import build_report_html
try:
    from src.api.report_aggregation import build_ingestion_report
    from src.api.dependencies import get_platform_state
except Exception:
    from .report_aggregation import build_ingestion_report  # type: ignore
    from .dependencies import get_platform_state  # type: ignore

try:
    from src.integrations.llm_client import generate_summary
except Exception:
    from ..integrations.llm_client import generate_summary
try:
    from src.reporting.llm_prompts import build_summary_prompt, parse_structured_summary
except Exception:
    from ..reporting.llm_prompts import build_summary_prompt, parse_structured_summary
try:
    import bleach
    _HAS_BLEACH = True
except Exception:
    bleach = None
    _HAS_BLEACH = False
import io
import re

def _simple_sanitize(html: str) -> str:
    # Very small fallback sanitizer: remove script/style tags and on* attributes
    html = re.sub(r'(?is)<script.*?>.*?</script>', '', html)
    html = re.sub(r'(?is)<style.*?>.*?</style>', '', html)
    # remove on* attributes like onclick
    html = re.sub(r'\son\w+="[^"]*"', '', html)
    html = re.sub(r"\son\w+='[^']*'", '', html)
    return html

_STREAM_THRESHOLD = int(__import__('os').environ.get('REPORT_STREAM_THRESHOLD_BYTES', '16384'))

router = APIRouter()


def _parse_sessions_param(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [token.strip() for token in raw.split(',') if token.strip()]


def _parse_recipients(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [addr.strip() for addr in raw.split(',') if addr.strip()]


def _persona_from_variant(variant: str | None, override: str | None) -> str:
    if override:
        derived = override.strip().lower()
        if derived:
            return derived
    mapping = {
        'executive': 'executive',
        'exec': 'executive',
        'soc': 'soc_analyst',
        'soc_analyst': 'soc_analyst',
        'technical': 'soc_analyst',
        'hunter': 'threat_hunter',
        'threat_hunter': 'threat_hunter',
        'compliance': 'compliance',
        'mssp': 'soc_analyst',
    }
    key = (variant or '').strip().lower()
    return mapping.get(key, 'soc_analyst')


def _report_to_csv(report: dict[str, Any]) -> str:
    lines: list[str] = []
    meta = report.get('meta') or {}
    if meta.get('persona'):
        lines.append(f"persona,selected,{meta.get('persona')}")
    if meta.get('variant'):
        lines.append(f"persona,variant,{meta.get('variant')}")
    verdict_stats = report.get('verdict_stats') or {}
    for key, value in verdict_stats.items():
        lines.append(f"verdict_stats,{key},{value}")
    severity = report.get('severity_distribution') or {}
    for key, value in severity.items():
        lines.append(f"severity_distribution,{key},{value}")
    for item in report.get('top_mitre', []) or []:
        lines.append(f"top_mitre,{item.get('technique')},{item.get('count')}")
    alerts = report.get('alerts') or []
    lines.append(f"alerts,total,{len(alerts)}")
    lines.append(f"network_artifacts,total,{len(report.get('network_artifacts') or [])}")
    network_highlights = report.get('network_highlights') or {}
    for talker in (network_highlights.get('top_talkers') or []):
        lines.append(
            "network_top_talker,"
            + ",".join(
                [
                    str(talker.get('ip') or ''),
                    str(talker.get('count') or 0),
                    str(talker.get('stage') or ''),
                ]
            )
        )
    for beacon in (network_highlights.get('beacon_findings') or []):
        lines.append(
            "network_beacon,"
            + ",".join(
                [
                    str(beacon.get('src_ip') or ''),
                    str(beacon.get('dst_ip') or ''),
                    str(beacon.get('score') or ''),
                ]
            )
        )
    for artifact in report.get('network_artifacts') or []:
        try:
            payload = artifact.get('data')
            serialized = json.dumps(payload, separators=(',', ':')) if payload is not None else ''
        except Exception:
            serialized = ''
        lines.append(
            "network_artifact,"
            + ",".join(
                [
                    str(artifact.get('type') or ''),
                    serialized.replace('\n', ' '),
                ]
            )
        )
    finops = report.get('finops') or {}
    if finops:
        lines.append(f"finops,ingest_cost_estimate,{finops.get('ingest_cost_estimate')}")
        lines.append(f"finops,storage_cost_estimate,{finops.get('storage_cost_estimate')}")
        lines.append(f"finops,net_savings_estimate,{finops.get('net_savings_estimate')}")
    return '\n'.join(lines)


def _build_html_payload(report: dict[str, Any], session_ids: list[str], recipients: list[str]) -> dict[str, Any]:
    meta = dict(report.get('meta') or {})
    if recipients:
        meta['recipients'] = recipients
    payload = {
        'title': 'Investigation Report',
        'session_id': ', '.join(session_ids) if session_ids else '',
        'rows': report.get('flagged_events', []),
        'summary': {
            'verdict_stats': report.get('verdict_stats'),
            'severity_distribution': report.get('severity_distribution'),
            'finops': report.get('finops'),
        },
        'correlation': report.get('network_highlights'),
        'meta': meta,
        'network_highlights': report.get('network_highlights'),
        'top_mitre': report.get('top_mitre'),
    }
    # Compose email sections using Tier1/Tier2 summaries when available
    try:
        rows = report.get('flagged_events') or []
        # Collect recent click context mapped by message_id
        click_map = {}
        if fetch_recent_clicks:
            try:
                for c in fetch_recent_clicks(limit=200) or []:
                    mid = c.get('message_id')
                    if not mid:
                        continue
                    lst = click_map.setdefault(mid, [])
                    lst.append({
                        'user': c.get('user'),
                        'ip': (c.get('meta') or {}).get('ip') if isinstance(c.get('meta'), dict) else None,
                        'ua': (c.get('meta') or {}).get('ua') if isinstance(c.get('meta'), dict) else None,
                        'url': c.get('url'),
                        'verdict': c.get('verdict'),
                        'mapping_confidence': 1.0,  # exact message_id match
                    })
            except Exception:
                click_map = {}
        cb = ChainBuilder() if ChainBuilder else None
        email_t1: list[dict[str, Any]] = []
        email_t2: list[dict[str, Any]] = []
        email_chains: list[dict[str, Any]] = []
        for r in rows:
            src = (r.get('source_platform') or '').lower()
            is_email = src in {'proofpoint', 'mimecast', 'report_phish_mailbox'} or bool(r.get('sender') or r.get('sender_domain'))
            if not is_email:
                continue
            # Attach click context into raw_event
            re = r.setdefault('raw_event', {})
            mid = r.get('message_id')
            if mid and click_map.get(mid):
                re['click_events'] = click_map[mid]
            chain = None
            if cb:
                try:
                    chain = cb.build_or_update(email_event=None, identity_events=[], devops_events=[], endpoint_events=[], window_seconds=24*3600)
                except Exception:
                    chain = None
            email_t1.append(tier1_summary(r, chain))
            email_t2.append(tier2_summary(r, chain))
            if chain:
                email_chains.append({
                    'chain_id': getattr(chain, 'chain_id', None),
                    'confidence': getattr(chain, 'confidence', 0.0),
                    'stages': [
                        {
                            'domain': getattr(s, 'domain', ''),
                            'event_id': getattr(s, 'event_id', ''),
                            'timestamp': getattr(s, 'timestamp', 0.0),
                            'confidence': getattr(s, 'confidence', 0.0),
                        } for s in getattr(chain, 'stages', []) or []
                    ],
                })
        if email_t1:
            payload['email_summaries'] = email_t1
            payload['email_details'] = email_t2
            payload['email_chains'] = email_chains
    except Exception:
        # Non-fatal: continue without email sections
        pass
    return payload


@router.get('/api/v1/report/ingestion')
async def report_ingestion(
    request: Request,
    format: str = Query('html'),
    include_alerts: bool = Query(True),
    limit_alerts: int = Query(150, ge=0, le=1000),
    alerts_offset: int = Query(0, ge=0),
    include_model: bool = Query(False),
    include_scenarios: bool = Query(False),
    include_suppressed_vex: bool = Query(False),
    sessions: str | None = Query(None),
    variant: str | None = Query(None),
    persona: str | None = Query(None),
    recipients: str | None = Query(None),
    tenant: str | None = Query(None),
) -> Any:
    fmt = (format or 'html').strip().lower()
    session_ids = _parse_sessions_param(sessions)
    persona_selected = _persona_from_variant(variant, persona)
    tenant_id = tenant or request.headers.get('X-Tenant-ID') or request.headers.get('x-tenant-id')
    state = get_platform_state()
    report = build_ingestion_report(
        session_ids,
        include_alerts,
        limit_alerts,
        state,
        tenant_id=tenant_id,
        alerts_offset=alerts_offset,
        include_scenarios=include_scenarios,
        include_model=include_model,
        include_suppressed_vex=include_suppressed_vex,
        persona=persona_selected,
        variant=variant,
    )
    recipients_list = _parse_recipients(recipients)
    meta = report.setdefault('meta', {})
    if tenant_id:
        meta.setdefault('tenant_id', tenant_id)
    if session_ids:
        meta['sessions'] = session_ids
    if recipients_list:
        meta['recipients'] = recipients_list
    meta['persona'] = persona_selected
    meta['variant'] = (variant or '').strip().lower() or meta.get('variant')
    meta['format'] = fmt

    if fmt == 'json':
        return JSONResponse(report)
    if fmt == 'csv':
        csv_text = _report_to_csv(report)
        return PlainTextResponse(content=csv_text, media_type='text/csv')
    if fmt == 'html':
        payload = _build_html_payload(report, session_ids, recipients_list)
        html = build_report_html(payload)
        # Optionally include model summary into HTML (sanitized)
        if include_model:
            try:
                prompt = build_summary_prompt(payload.get('summary') or {}, len(payload.get('rows') or []))
                llm_resp = generate_summary(prompt, max_tokens=512)
                if hasattr(llm_resp, '__await__'):
                    llm_resp = await llm_resp
                model_text = llm_resp.get('text') if isinstance(llm_resp, dict) else str(llm_resp)
                model_html = '<div style="padding:12px;background:#071021;color:#e6eef8;border-radius:6px"><h3>Model Executive Summary</h3><div>' + escape(str(model_text or '')) + '</div></div>'
                try:
                    if _HAS_BLEACH:
                        model_html = bleach.clean(model_html, tags=bleach.sanitizer.ALLOWED_TAGS + ['div','h3','pre','code','span'], attributes=bleach.sanitizer.ALLOWED_ATTRIBUTES, strip=True)
                    else:
                        model_html = _simple_sanitize(model_html)
                except Exception:
                    pass
                html = model_html + '\n' + html
            except Exception:
                # non-fatal; return HTML without model summary
                pass
        return HTMLResponse(content=html)
    if fmt == 'pdf':
        return JSONResponse({'detail': 'pdf_generation_not_enabled'}, status_code=501)
    raise HTTPException(status_code=400, detail='unsupported_format')


@router.post('/api/v1/report/generate_pdf')
async def generate_pdf_report(req: Request, include_model: bool = Query(False)):
    """Generate a PDF from the standard HTML report. Uses WeasyPrint when available.

    Fallback: if WeasyPrint isn't installed or fails, return the HTML as a StreamingResponse
    with `text/html` so the frontend can fall back to downloading HTML.
    """
    payload = await req.json()
    html = build_report_html(payload)
    # Optionally include model summary into HTML
    if include_model:
        try:
            prompt = build_summary_prompt(payload.get('summary') or {}, len(payload.get('rows') or []))
            llm_resp = generate_summary(prompt, max_tokens=512)
            if hasattr(llm_resp, '__await__'):
                llm_resp = await llm_resp
            model_text = llm_resp.get('text') if isinstance(llm_resp, dict) else str(llm_resp)
            # simple injection
            model_html = '<div style="padding:12px;background:#071021;color:#e6eef8;border-radius:6px"><h3>Model Executive Summary</h3><div>' + escape(str(model_text or '')) + '</div></div>'
            html = model_html + '\n' + html
        except Exception:
            # continue without model
            pass

    try:
        from src.reporting.export import export_pdf_bytes_from_html
    except Exception:
        export_pdf_bytes_from_html = None

    if export_pdf_bytes_from_html is not None:
        try:
            pdf_bytes = export_pdf_bytes_from_html(html)
            if pdf_bytes:
                import io
                return StreamingResponse(io.BytesIO(pdf_bytes), media_type='application/pdf', headers={'Content-Disposition': 'attachment; filename="report.pdf"'})
        except Exception:
            pass

    # Fallback: return HTML content
    buf = html.encode('utf-8')
    return StreamingResponse(io.BytesIO(buf), media_type='text/html')


@router.post('/api/v1/report/generate')
async def generate_report(req: Request, format: str = Query('html'), include_model: bool = Query(False), include_scenarios: bool = Query(False)):
    payload = await req.json()
    # payload may include: session_id, rows (list), summary
    # Build the HTML or JSON output
    html = build_report_html(payload)
    result = {'html': html}

    # Optionally request an LLM summary and attach provenance
    if include_model:
        prompt = f"Summarize the following report: {payload.get('summary') or ''}\nContext rows: {len(payload.get('rows') or [])}"
        try:
            # build a structured prompt
            prompt = build_summary_prompt(payload.get('summary') or {}, len(payload.get('rows') or []))
            # generate_summary may be sync; allow both sync and async returns
            llm_resp = generate_summary(prompt, max_tokens=512)
            if hasattr(llm_resp, '__await__'):
                llm_resp = await llm_resp
            # Attach provenance metadata into result
            model_text = llm_resp.get('text') if isinstance(llm_resp, dict) else str(llm_resp)
            result['model_summary'] = {
                'text': model_text,
                'model': llm_resp.get('model') if isinstance(llm_resp, dict) else None,
                'meta': llm_resp.get('meta') if isinstance(llm_resp, dict) else None,
                'provenance': {}
            }
            # Attempt to parse structured JSON summary from model text
            try:
                parsed = parse_structured_summary(model_text or '')
                result['model_summary']['provenance']['structured'] = parsed
            except Exception:
                pass
            # Create a compact model_html snippet (sanitized below)
            model_html = '<div style="padding:12px;background:#071021;color:#e6eef8;border-radius:6px"><h3>Model Executive Summary</h3><div>' + escape(str(model_text or '')) + '</div></div>'
            result['model_html'] = model_html
        except Exception as e:
            result['model_summary'] = {'error': str(e)}

    # Sanitize HTML output to avoid XSS
    try:
        if _HAS_BLEACH:
            safe_html = bleach.clean(html, tags=bleach.sanitizer.ALLOWED_TAGS + ['table', 'tr', 'td', 'th'], attributes=bleach.sanitizer.ALLOWED_ATTRIBUTES, strip=True)
        else:
            safe_html = _simple_sanitize(html)
    except Exception:
        safe_html = html

    # Sanitize model_html if present
    try:
        if result.get('model_html'):
            if _HAS_BLEACH:
                result['model_html'] = bleach.clean(result['model_html'], tags=bleach.sanitizer.ALLOWED_TAGS + ['div','h3','pre','code','span'], attributes=bleach.sanitizer.ALLOWED_ATTRIBUTES, strip=True)
            else:
                result['model_html'] = _simple_sanitize(result['model_html'])
    except Exception:
        pass

    if format == 'html':
        # If include_model requested, return JSON (avoid embedding raw model text into HTML)
        if include_model:
            return JSONResponse(result)
        # Stream large HTML responses to avoid memory pressure
        buf = safe_html.encode('utf-8')
        if len(buf) > _STREAM_THRESHOLD:
            return StreamingResponse(io.BytesIO(buf), media_type='text/html')
        return HTMLResponse(content=safe_html, status_code=200)
    else:
        return JSONResponse(result)


# ---------------- Persona View Endpoints -----------------
try:
    # Snapshot loader for stored ingestion/executive reports
    from src.repositories.report_snapshots_repo import load_snapshot
except Exception:
    try:
        from ..repositories.report_snapshots_repo import load_snapshot
    except Exception:
        load_snapshot = None  # type: ignore
try:
    from src.reporting.persona_views import generate_persona_view
except Exception:
    from ..reporting.persona_views import generate_persona_view

try:
    from src.repositories.feedback_repo import insert_report_feedback, get_feedback_for_report, insert_feedback
except Exception:
    insert_report_feedback = None  # type: ignore
    get_feedback_for_report = None  # type: ignore
    insert_feedback = None  # type: ignore

from pathlib import Path
import os
import math
from statistics import mean
try:
    from src.repositories.audit_repo import insert_audit, list_audits
except Exception:
    try:
        from ..repositories.audit_repo import insert_audit, list_audits
    except Exception:
        insert_audit = None  # type: ignore
        list_audits = None  # type: ignore

_SNAP_BASE = Path('reports') / 'snapshots'

from src.reporting.attention_queue import categorize_reports
try:
    # Reuse centralized persona parser/validator when persona-like text is present
    from src.reporting.persona_parser import parse_persona_text, validate_parsed_persona
except Exception:
    parse_persona_text = None  # type: ignore
    validate_parsed_persona = None  # type: ignore


def _compute_attention_score(rpt: dict) -> float:
    """Compute an attention score blending severity, confidence, dependency health, and age."""
    try:
        sev_map = {'CRITICAL': 1.0, 'HIGH': 0.8, 'MEDIUM': 0.5, 'LOW': 0.2}
        sev = (rpt.get('risk_quantification', {}).get('severity') or 'LOW').upper()
        s = sev_map.get(sev, 0.2)
        conf = float(rpt.get('verdict', {}).get('final_confidence', 0.0))
        dep = rpt.get('dependency_status', {})
        seconds_since_ok = float(dep.get('seconds_since_ok', 0) or 0)
        dep_penalty = 0.0 if seconds_since_ok <= 300 else min(0.3, (seconds_since_ok / 3600.0) * 0.05)
        ts = float(rpt.get('generated_at') or rpt.get('ts') or time.time())
        age_hours = max(0.0, (time.time() - ts) / 3600.0)
        age_score = 0.0 if age_hours < 1 else min(0.3, age_hours / 24.0)
        # attention score: severity*0.5 + (1-confidence)*0.3 + dep_penalty + age_score
        score = (s * 0.5) + ((1.0 - conf) * 0.3) + dep_penalty + age_score
        return float(score)
    except Exception:
        return 0.0


@router.get('/api/v1/reports/attention')
async def reports_attention(limit: int = Query(50)):
    """Return attention buckets and a triage scoreboard (top-N by attention score).

    For demo mode this scans snapshots in `reports/snapshots` and computes buckets.
    """
    # Load snapshots from disk (best-effort); prefer snapshot loader when available
    snaps = []
    try:
        if load_snapshot:
            # When DB-backed snapshots exist, list via the repo (fallback to file scan)
            try:
                from src.repositories.report_snapshots_repo import list_snapshots, load_snapshot as _ls
                meta = list_snapshots(limit=limit)
                for m in meta:
                    p = _ls(m.get('report_id'))
                    if p:
                        snaps.append(p)
            except Exception:
                pass
        # fallback: scan reports/snapshots
        for p in _SNAP_BASE.glob('*.json'):
            try:
                import json
                data = json.loads(p.read_text(encoding='utf-8'))
                payload = data.get('payload')
                if payload:
                    snaps.append(payload)
            except Exception:
                continue
    except Exception:
        snaps = []

    buckets = categorize_reports(snaps)

    # Build triage scoreboard
    scored = []
    for s in snaps:
        try:
            rpt_id = s.get('report_id')
            score = _compute_attention_score(s)
            scored.append({'report_id': rpt_id, 'score': score, 'summary': s.get('summary') or {}, 'decision_gates': s.get('decision_gates', [])})
        except Exception:
            continue
    scored_sorted = sorted(scored, key=lambda x: x.get('score', 0.0), reverse=True)
    triage = scored_sorted[:5]
    return JSONResponse({'buckets': buckets, 'triage_scoreboard': triage})


@router.post('/api/v1/reports/{report_id}/route')
async def route_report(report_id: str, payload: dict, request: Request, persona: str = Query('executive'), disclosure_level: int = Query(2)):
    """Route a stored report to one or more personas and persist an audit entry.

    Payload must include `recipients` list (optional) and `note`.
    """
    # Basic auth guard: require console API key or admin
    api_key = request.headers.get('x-api-key') or request.headers.get('X-API-Key')
    # Best-effort: allow when running in lite/demo mode
    if not api_key and os.getenv('PLATFORM_LITE_INIT','0').lower() not in {'1','true','yes'}:
        raise HTTPException(status_code=401, detail='api_key_required')
    # load snapshot
    snap = None
    if load_snapshot:
        snap = load_snapshot(report_id)
    else:
        p = _SNAP_BASE / f"{report_id}.json"
        if p.exists():
            try:
                import json
                snap = json.loads(p.read_text(encoding='utf-8')).get('payload')
            except Exception:
                snap = None
    if not snap:
        raise HTTPException(status_code=404, detail='report_not_found')
    recipients = payload.get('recipients') or []
    note = payload.get('note')
    # Enforce risk appetite rules
    try:
        from src.repositories.risk_appetite_repo import load_profiles
        profiles = load_profiles()
        prof = profiles.get(persona) or profiles.get(persona.lower()) or {}
    except Exception:
        prof = {}
    # allow override via payload.force
    force = bool(payload.get('force'))
    current_conf = float(snap.get('verdict', {}).get('final_confidence', 0.0))
    expected_loss = int(snap.get('risk_quantification', {}).get('expected_loss_usd', 0) or 0)
    if prof and not force:
        min_conf = float(prof.get('min_confidence', 0.0) or 0.0)
        cap = prof.get('impact_cap_usd')
        require_cost = bool(prof.get('require_cost_summary'))
        if current_conf < min_conf:
            raise HTTPException(status_code=403, detail='risk_appetite_confidence_too_low')
        if cap and expected_loss and expected_loss > cap:
            raise HTTPException(status_code=403, detail='risk_appetite_cost_exceeds_cap')
        if require_cost and not snap.get('risk_quantification'):
            raise HTTPException(status_code=403, detail='risk_appetite_requires_cost_summary')

    # Build audit record
    audit = {
        'report_id': report_id,
        'persona': persona,
        'recipients': recipients,
        'disclosure_level': int(disclosure_level),
        'note': note,
        'sent_by': api_key,
        'sent_at': int(time.time()),
    }
    # Persist via audit_repo if available
    audit_id = None
    try:
        if insert_audit:
            audit_id = insert_audit(audit)
        else:
            # fallback to file for backwards compatibility
            audit_dir = Path('reports') / 'audits'
            audit_dir.mkdir(parents=True, exist_ok=True)
            try:
                import json
                fname = audit_dir / f"audit_{report_id}_{int(time.time())}.json"
                fname.write_text(json.dumps(audit), encoding='utf-8')
            except Exception:
                pass
    except Exception:
        pass

    # Optionally trigger existing export/report endpoints to send the snapshot
    # For demo we return the persisted audit id and a hint URL to use /api/v1/report/generate
    hint = f"/api/v1/report/generate?format=json&report_id={report_id}"
    resp = {'routed': True, 'audit': audit}
    if audit_id:
        resp['audit_id'] = audit_id
    resp['send_hint'] = hint
    return JSONResponse(resp)


@router.post('/api/v1/reports/{report_id}/send')
async def send_report(report_id: str, payload: dict, request: Request):
    """Automated sender: generate report HTML/JSON and POST to recipient endpoints.

    Payload: {recipients: [{url, method, headers?}], format: 'html'|'json', include_model: bool}
    """
    # basic guard
    api_key = request.headers.get('x-api-key') or request.headers.get('X-API-Key')
    if not api_key and os.getenv('PLATFORM_LITE_INIT','0').lower() not in {'1','true','yes'}:
        raise HTTPException(status_code=401, detail='api_key_required')
    # load snapshot (reuse logic)
    snap = None
    if load_snapshot:
        snap = load_snapshot(report_id)
    else:
        p = _SNAP_BASE / f"{report_id}.json"
        if p.exists():
            try:
                import json
                snap = json.loads(p.read_text(encoding='utf-8')).get('payload')
            except Exception:
                snap = None
    if not snap:
        raise HTTPException(status_code=404, detail='report_not_found')

    # Build the report via the existing generate_report route function (call locally)
    try:
        # create a shallow payload for generator
        gen_payload = snap
        include_model = bool(payload.get('include_model'))
        fmt = payload.get('format','html')
        # call generator function (imported above)
        # generate_report expects a Request-like object; call build_report_html directly
        html = build_report_html(gen_payload)
        result = {'html': html}
        if include_model:
            try:
                prompt = build_summary_prompt(gen_payload.get('summary') or {}, len(gen_payload.get('rows') or []))
                llm_resp = generate_summary(prompt, max_tokens=512)
                if hasattr(llm_resp, '__await__'):
                    llm_resp = await llm_resp
                model_text = llm_resp.get('text') if isinstance(llm_resp, dict) else str(llm_resp)
                result['model_summary'] = {'text': model_text}
            except Exception:
                pass
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'generate_failed:{e}')

    recipients = payload.get('recipients') or []
    # enqueue background delivery and persist audit immediately
    try:
        from src.services.delivery_queue import enqueue_delivery
        audit_record = {'report_id': report_id, 'action': 'send', 'recipients': recipients, 'ts': int(time.time())}
        aid = enqueue_delivery(audit_record, recipients, result if fmt != 'html' else result['html'])
    except Exception:
        aid = None

    resp = {'enqueued': True, 'audit_id': aid}
    return JSONResponse(resp)


# Admin endpoints to manage risk appetite profiles
try:
    from src.repositories.risk_appetite_repo import load_profiles, save_profiles
except Exception:
    load_profiles = None
    save_profiles = None


def _require_admin(request: Request) -> None:
    api_key = request.headers.get('x-api-key') or request.headers.get('X-API-Key')
    admin_key = os.getenv('ADMIN_API_KEY') or os.getenv('API_KEY')
    # Allow when running in lite/demo or fast test modes
    lite = os.getenv('PLATFORM_LITE_INIT','0').lower() in {'1','true','yes'}
    testmode = os.getenv('FAST_TEST_MODE','0').lower() in {'1','true','yes'}
    if not admin_key:
        if lite or testmode:
            return
        raise HTTPException(status_code=403, detail='admin_key_not_configured')
    if api_key != admin_key:
        raise HTTPException(status_code=401, detail='unauthorized')


@router.get('/api/v1/admin/risk_profiles')
async def get_risk_profiles(request: Request):
    # Admin-only guard
    _require_admin(request)
    if not load_profiles:
        raise HTTPException(status_code=503, detail='risk_profiles_unavailable')
    try:
        profiles = load_profiles()
        return JSONResponse(profiles)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'load_failed:{e}')


@router.post('/api/v1/admin/risk_profiles')
async def post_risk_profiles(request: Request, payload: dict):
    _require_admin(request)
    if not save_profiles:
        raise HTTPException(status_code=503, detail='risk_profiles_unavailable')
    try:
        # payload expected to be a mapping of profile_name -> settings
        save_profiles(payload)
        return JSONResponse({'ok': True})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'save_failed:{e}')


# Playbook action endpoints (isolate, block, create_ticket, export_intel)
try:
    from src.repositories.playbook_repo import get_playbook_for_verdict
except Exception:
    get_playbook_for_verdict = None


@router.post('/api/v1/actions/isolate')
async def action_isolate(payload: dict):
    # payload: {host, reason, report_id}
    # For demo, we record an audit and return an action_id
    try:
        audit = {'report_id': payload.get('report_id'), 'action': 'isolate', 'target': payload.get('host'), 'ts': int(time.time())}
        aid = None
        if insert_audit:
            aid = insert_audit(audit)
        return {'ok': True, 'action_id': aid}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post('/api/v1/actions/block')
async def action_block(payload: dict):
    # payload: {ioc, type, report_id}
    try:
        audit = {'report_id': payload.get('report_id'), 'action': 'block', 'target': payload.get('ioc'), 'ts': int(time.time())}
        aid = None
        if insert_audit:
            aid = insert_audit(audit)
        return {'ok': True, 'action_id': aid}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post('/api/v1/actions/create_ticket')
async def action_create_ticket(payload: dict):
    # payload: {title, description, report_id, priority}
    try:
        # Demo: return a fake ticket id and persist audit
        ticket_id = f"TKT-{int(time.time())}"
        audit = {'report_id': payload.get('report_id'), 'action': 'create_ticket', 'ticket_id': ticket_id, 'ts': int(time.time())}
        aid = None
        if insert_audit:
            aid = insert_audit(audit)
        return {'ok': True, 'ticket_id': ticket_id, 'action_id': aid}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post('/api/v1/actions/export_intel')
async def action_export_intel(payload: dict):
    # payload: {report_id, recipients}
    try:
        # For demo, call send_report to export to recipients
        report_id = payload.get('report_id')
        recipients = payload.get('recipients') or []
        resp = await send_report(report_id, {'recipients': recipients, 'format': 'json', 'include_model': False}, None)
        return resp
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



@router.post('/api/v1/reports/{report_id}/feedback')
async def capture_report_feedback(report_id: str, payload: dict, request: Request):
    """Capture feedback for a report row or overall report.

    Expected payload: {row_id, accurate: bool, comment, reviewer}
    Also supports factor-level voting via {factor, vote, comment}
    """
    # allow anonymous in lite mode
    reviewer = payload.get('reviewer') or request.headers.get('x-user') or 'unknown'
    # row-level feedback
    row_id = payload.get('row_id')
    accurate = payload.get('accurate')
    comment = payload.get('comment')
    try:
        if row_id is not None:
            if insert_report_feedback:
                await insert_report_feedback(report_id, row_id, None, bool(accurate), comment, reviewer)
            else:
                # fallback file append
                fb_dir = Path('reports') / 'feedback'
                fb_dir.mkdir(parents=True, exist_ok=True)
                import json
                fp = fb_dir / f"feedback_{report_id}.jsonl"
                fp.write_text(json.dumps({'report_id': report_id, 'row_id': row_id, 'accurate': bool(accurate), 'comment': comment, 'reviewer': reviewer, 'ts': int(time.time())}) + '\n', encoding='utf-8', append=False)
    except Exception:
        raise HTTPException(status_code=500, detail='feedback_store_failed')
    # factor vote
    factor = payload.get('factor')
    vote = payload.get('vote')
    if factor and vote is not None:
        try:
            if insert_feedback:
                await insert_feedback(f"{report_id}:{row_id or '*'}", factor, int(vote), comment, None)
        except Exception:
            pass
    return {'ok': True}


@router.get('/api/v1/reports/{report_id}/persona_view')
async def get_persona_view(report_id: str, persona: str = Query('executive'), disclosure_level: int = Query(2)):
    """Return a persona-specific view for a stored report snapshot.

    Loads the report payload via the snapshots repo and composes a concise
    persona view including summary signals and decision gates.
    """
    if load_snapshot is None:
        raise HTTPException(status_code=503, detail='snapshot_loader_unavailable')
    payload = load_snapshot(report_id)
    if not payload:
        raise HTTPException(status_code=404, detail='report_not_found')
    try:
        view = generate_persona_view(payload, persona=persona, disclosure_level=int(disclosure_level))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'persona_build_failed:{exc}')
    # Defensive: if view contains persona-like free text blocks, validate
    try:
        if parse_persona_text and validate_parsed_persona:
            # Common shapes to inspect: view['persona_reports'][key]['text'] or view['text']
            texts: list[str] = []
            try:
                pr = view.get('persona_reports') if isinstance(view, dict) else None
                if isinstance(pr, dict):
                    for _k, entry in pr.items():
                        t = (entry or {}).get('text') if isinstance(entry, dict) else None
                        if isinstance(t, str) and t.strip():
                            texts.append(t)
            except Exception:
                pass
            # Singular text key
            try:
                t0 = view.get('text') if isinstance(view, dict) else None
                if isinstance(t0, str) and t0.strip():
                    texts.append(t0)
            except Exception:
                pass
            # Attach aggregate validation summary if any persona-like texts present
            validations = []
            for t in texts[:3]:  # cap to small number defensively
                try:
                    parsed = parse_persona_text(t)
                except Exception:
                    parsed = None
                try:
                    if parsed is not None:
                        ok, errs = validate_parsed_persona(parsed)  # type: ignore
                        validations.append({'ok': bool(ok), 'errors': errs or [], 'confidence': parsed.get('confidence')})
                    else:
                        validations.append({'ok': False, 'errors': ['parse_failed']})
                except Exception:
                    validations.append({'ok': False, 'errors': ['validation_error']})
            if validations:
                view.setdefault('validation', {})
                view['validation'].setdefault('persona_text_checks', validations)
    except Exception:
        # Non-fatal; continue returning the persona view
        pass
    return JSONResponse(view)


@router.post('/api/v1/reports/persona_view')
async def post_persona_view(req: Request, persona: str = Query('executive'), disclosure_level: int = Query(2)):
    """Build a persona view from an inline report payload.

    Accepts a JSON body containing the report structure and returns a
    persona-specific view. Useful for LIVE console previews without
    persisting a snapshot first.
    """
    try:
        payload = await req.json()
    except Exception:
        raise HTTPException(status_code=400, detail='invalid_json')
    try:
        view = generate_persona_view(payload, persona=persona, disclosure_level=int(disclosure_level))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'persona_build_failed:{exc}')
    # Defensive persona text validation as above
    try:
        if parse_persona_text and validate_parsed_persona and isinstance(view, dict):
            texts: list[str] = []
            pr = view.get('persona_reports') if isinstance(view, dict) else None
            if isinstance(pr, dict):
                for _k, entry in pr.items():
                    t = (entry or {}).get('text') if isinstance(entry, dict) else None
                    if isinstance(t, str) and t.strip():
                        texts.append(t)
            t0 = view.get('text') if isinstance(view, dict) else None
            if isinstance(t0, str) and t0.strip():
                texts.append(t0)
            validations = []
            for t in texts[:3]:
                try:
                    parsed = parse_persona_text(t)
                except Exception:
                    parsed = None
                try:
                    if parsed is not None:
                        ok, errs = validate_parsed_persona(parsed)  # type: ignore
                        validations.append({'ok': bool(ok), 'errors': errs or [], 'confidence': parsed.get('confidence')})
                    else:
                        validations.append({'ok': False, 'errors': ['parse_failed']})
                except Exception:
                    validations.append({'ok': False, 'errors': ['validation_error']})
            if validations:
                view.setdefault('validation', {})
                view['validation'].setdefault('persona_text_checks', validations)
    except Exception:
        pass
    return JSONResponse(view)
