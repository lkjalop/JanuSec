from fastapi import APIRouter, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from html import escape
try:
    # Prefer absolute import when running under normal package layout
    from src.reporting.comprehensive_report_generator import build_report_html
except Exception:
    # Fallback to relative import when package context is different (tests may import `api` as top-level)
    from ..reporting.comprehensive_report_generator import build_report_html

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
