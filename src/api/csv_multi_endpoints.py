from fastapi import APIRouter, File, UploadFile, Request, Form
from typing import Dict, Any, Optional
from .csv_handler import parse_csv_bytes, forward_rows, async_forward_rows
import json
import requests
from fastapi.testclient import TestClient
import uuid, time
import os
router = APIRouter(prefix="/api/v1/csv_multi", tags=["csv_multi"])


@router.post('/upload', operation_id='csv_multi_upload')
async def upload_csv(file: UploadFile = File(...), request: Request = None, mapping: Optional[str] = Form(None)):
    content = await file.read()
    rows = parse_csv_bytes(content)
    mapping_obj = None
    if mapping:
        try:
            mapping_obj = json.loads(mapping)
        except Exception:
            mapping_obj = None
    # heuristic detection based on first header presence
    def _detect_kind(sample: dict[str, any]) -> str:
        ks = {str(k).lower() for k in (sample.keys() if isinstance(sample, dict) else [])}
        # Remote access (VPN/RDP/SSH/Bastion)
        if any(k in ks for k in ('src_ip', 'source_ip', 'client_ip')) and (
            any(k in ks for k in ('dest_host', 'dst_host', 'host')) or 'protocol' in ks or any(k in ks for k in ('vpn_endpoint','gateway'))
        ):
            return 'remote_access'
        # Email
        if 'from' in ks and 'subject' in ks:
            return 'email'
        # AI domain (model/prompt/tool/etc.)
        if any(k in ks for k in (
            'model','provider','model_provider','prompt','tool','tool_name','embedding_id','vector_db','rag_index','guardrail','chain','agent','feature_store','dataset'
        )):
            return 'ai'
        # Data access (DB logs)
        if any(k in ks for k in ('database', 'db')) or (
            'query' in ks or 'sql' in ks
        ):
            return 'data_access'
        # API Gateway / API security (various vendors)
        if any(k in ks for k in ('request_uri', 'uri', 'path', 'request', 'message', 'status', 'httpmethod', 'method')):
            # Specific flavors
            if any(k in ks for k in ('x_rate_limit_remaining', 'ratelimit_remaining', 'consumer')):
                return 'api_kong'
            if any(k in ks for k in ('developer_email', 'apiproxy', 'request_path', 'status_code')):
                return 'api_apigee'
            if any(k in ks for k in ('operationname', 'backendurl', 'apim')):
                return 'api_azure'
            if any(k in ks for k in ('requestid', 'httpmethod', 'stage')):
                return 'api_aws'
            if any(k in ks for k in ('httprequest.requestmethod', 'protopayload')):
                return 'api_gcp'
            return 'api_nginx'
        return 'unknown'

    kind = 'unknown'
    if rows:
        kind = _detect_kind(rows[0])

    # choose post_func: use in-process TestClient if request contains header x-test-inproc=1
    post_func = None
    try:
        hdr = request.headers.get('x-test-inproc') if request else None
        if hdr and hdr == '1':
            # create TestClient around the same app instance
            tc = TestClient(request.app)
            def _post(path, json=None):
                # log when running under pytest to help triage inproc forwarding
                try:
                    if request and (request.headers.get('x-test-inproc') == '1' or os.getenv('DEBUG_CSV_FORWARD') == '1'):
                        import logging as _logging
                        _logging.getLogger(__name__).debug("inproc post to %s payload_keys=%s", path, list(json.keys()) if isinstance(json, dict) else None)
                except Exception:
                    pass
                return tc.post(path, json=json)
            post_func = _post
    except Exception:
        post_func = None

    if post_func is None:
        def _http_post(path, json=None):
            url = f"http://localhost:8080{path}"
            try:
                headers = {}
                if request is not None:
                    key = request.headers.get('x-api-key') or request.headers.get('X-API-Key')
                    if key:
                        headers['x-api-key'] = key
                return requests.post(url, json=json, headers=headers)
            except Exception:
                class R: status_code = 500
                return R()
        post_func = _http_post

    # Apply mapping if provided: mapping is dict like {"src_ip":"client_ip","user":"username"}
    if mapping_obj:
        mapped_rows = []
        for r in rows:
            nr = {}
            for dest, src in mapping_obj.items():
                nr[dest] = r.get(src) if isinstance(r, dict) else None
            # keep raw fallback
            nr['raw'] = r
            mapped_rows.append(nr)
        rows = mapped_rows
        # Re-evaluate kind after mapping if mapping provided so we forward to correct endpoint
        if rows:
            kind = _detect_kind(rows[0])
    session_id = 'sess-' + uuid.uuid4().hex
    session = {
        'session_id': session_id,
        'created_ts': int(time.time()),
        'kind': kind,
        'mapping': mapping or 'auto',
        'total_rows': len(rows)
    }

    # Use async forwarder to integrate with FastAPI
    try:
        # if using in-process TestClient, forward via async_forward_rows against TestClient is tricky since TestClient is sync.
        # Instead, when x-test-inproc is present we will use the sync forward_rows wrapper which runs the async forwarder internally.
        if request and request.headers.get('x-test-inproc') == '1':
            summary = forward_rows(rows, kind, post_func)
        else:
            summary = await async_forward_rows(rows, kind, base_url='http://localhost:8080')
    except Exception:
        summary = {'forwarded': 0, 'failed': 0, 'errors': ['forward_error']}
    session['forwarded'] = summary.get('forwarded', 0)
    session['failed'] = summary.get('failed', 0)
    session['errors'] = summary.get('errors', [])
    return {'status': 'processed', 'session': session}
