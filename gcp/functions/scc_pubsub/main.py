import base64
import hashlib
import json
import os
import random
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

import requests
from google.cloud import secretmanager  # type: ignore

DEFAULT_TIMEOUT = int(os.getenv('HTTP_TIMEOUT', '8'))
MAX_RETRIES = int(os.getenv('HTTP_MAX_RETRIES', '4'))
BACKOFF_BASE = float(os.getenv('HTTP_BACKOFF_BASE', '0.35'))
DLQ_PATH = os.getenv('GCP_SCC_FUNC_DLQ_PATH', 'data/dlq/gcp_scc_cloudfunc.jsonl')
TENANT_MAPPING_JSON = os.getenv('TENANT_MAPPING_JSON')
TENANT_ALLOWLIST = set([t.strip() for t in (os.getenv('TENANT_ALLOWLIST','').split(',') if os.getenv('TENANT_ALLOWLIST') else []) if t.strip()])
TENANT_PAUSE_LIST = set([t.strip() for t in (os.getenv('TENANT_PAUSE_LIST','').split(',') if os.getenv('TENANT_PAUSE_LIST') else []) if t.strip()])

_SECRET_CACHE: Dict[str, str] = {}


def _norm_str(v: Any) -> str:
    return '' if v is None else str(v)


def _choose_type(category_lower: str) -> Optional[str]:
    if 'public' in category_lower and ('bucket' in category_lower or 'storage' in category_lower):
        return 'cloud:public_bucket'
    if 'open firewall' in category_lower or '0.0.0.0/0' in category_lower or 'allow all' in category_lower:
        return 'cloud:sg_open_0_0_0_0'
    if 'cmek' in category_lower and ('missing' in category_lower or 'disabled' in category_lower):
        return 'cloud:cmek_missing'
    if 'iam' in category_lower and ('over-permission' in category_lower or 'overly permissive' in category_lower or 'wildcard' in category_lower):
        return 'cloud:iam_over_permission'
    if 'vulnerable image' in category_lower or 'container vulnerability' in category_lower:
        return 'cloud:image_vulnerable'
    return None


def _build_payloads_from_findings(findings: List[Dict[str, Any]], tenant: Optional[str]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    posture_findings: List[Dict[str, Any]] = []
    assets: List[Dict[str, Any]] = []
    for f in findings:
        cat_raw = _norm_str(f.get('category') or f.get('Category'))
        cat = cat_raw.lower()
        sev = (_norm_str(f.get('severity') or f.get('Severity') or 'low')).lower()
        r = _norm_str(f.get('resourceName') or f.get('resource'))
        src_ts = _norm_str(f.get('eventTime') or f.get('event_time') or f.get('createTime') or f.get('updateTime'))
        if r:
            assets.append({'id': r, 'service': ('storage' if 'storage' in r.lower() else 'gcp'), 'cloud': 'gcp', 'tenant_id': tenant})
        ftype = _choose_type(cat)
        if ftype:
            pf = {'type': ftype, 'severity': sev or 'low', 'resource': r or cat_raw or ftype, 'service': 'gcp', 'tenant_id': tenant}
            if src_ts:
                pf['source_ts'] = src_ts
            posture_findings.append(pf)

    posture = {'findings': posture_findings, 'tenant_id': tenant}
    assets_payload = {'assets': assets}
    return posture, assets_payload


def _calc_batch_id(posture_payload: Dict[str, Any]) -> str:
    parts: List[str] = []
    for f in posture_payload.get('findings', []):
        parts.append('|'.join([
            _norm_str(f.get('type')),
            _norm_str(f.get('resource')),
            _norm_str(f.get('source_ts'))
        ]))
    digest = hashlib.sha256(('\n'.join(sorted(parts))).encode('utf-8')).hexdigest()
    return digest


def _load_tenant_mapping() -> Dict[str, Any]:
    if not TENANT_MAPPING_JSON:
        return {}
    try:
        with open(TENANT_MAPPING_JSON, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def _extract_project_id(resource_name: str) -> Optional[str]:
    # Examples: //storage.googleapis.com/projects/_/buckets/x or //compute.googleapis.com/projects/p/...
    key = '/projects/'
    try:
        idx = resource_name.index(key)
        rest = resource_name[idx + len(key):]
        pid = rest.split('/')[0]
        if pid and pid != '_':
            return pid
    except Exception:
        return None
    return None


def _resolve_tenant(findings: List[Dict[str, Any]], default_tenant: Optional[str]) -> Optional[str]:
    mapping = _load_tenant_mapping()
    projects = mapping.get('projects') or {}
    for f in findings:
        rn = _norm_str(f.get('resourceName') or f.get('resource'))
        pid = _extract_project_id(rn) if rn else None
        if pid and pid in projects:
            return projects[pid]
    return mapping.get('default_tenant') or default_tenant


def _get_secret(secret_resource: str) -> Optional[str]:
    if secret_resource in _SECRET_CACHE:
        return _SECRET_CACHE[secret_resource]
    try:
        client = secretmanager.SecretManagerServiceClient()
        resp = client.access_secret_version(name=secret_resource)
        val = resp.payload.data.decode('utf-8')
        _SECRET_CACHE[secret_resource] = val
        return val
    except Exception as exc:
        print('Secret fetch failed:', exc)
        return None


def _post_with_retries(session: requests.Session, url: str, headers: Dict[str, str], payload: Dict[str, Any], timeout: int) -> int:
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = session.post(url, headers=headers, json=payload, timeout=timeout)
            if 200 <= r.status_code < 300:
                return r.status_code
            if r.status_code in (409, 429) or 500 <= r.status_code < 600:
                raise RuntimeError(f'HTTP {r.status_code}')
            return r.status_code
        except Exception:
            if attempt == MAX_RETRIES:
                raise
            backoff = BACKOFF_BASE * (2 ** (attempt - 1)) + random.uniform(0, 0.2)
            time.sleep(backoff)
    return 0


def pubsub_entry(event, context):  # Google Cloud Functions entry point
    base = (os.getenv('PLATFORM_API_BASE') or 'http://localhost:8080').rstrip('/')
    api_key = os.getenv('PLATFORM_API_KEY') or os.getenv('API_KEY')
    if not api_key:
        secret_res = os.getenv('PLATFORM_API_KEY_SECRET')
        if secret_res:
            api_key = _get_secret(secret_res)
    api_key = api_key or 'devkey123'
    default_tenant = os.getenv('TENANT_ID')
    tls_enforce = os.getenv('TLS_ENFORCE', '0')
    if tls_enforce not in ('0','false','False','no','NO') and not base.startswith('https://'):
        print('TLS_ENFORCE=1 but PLATFORM_API_BASE is not HTTPS, refusing egress')
        return 'tls_enforced', 200

    # Extract SCC findings from Pub/Sub message
    data = event.get('data')
    findings: List[Dict[str, Any]] = []
    if data:
        decoded = base64.b64decode(data).decode('utf-8')
        try:
            doc = json.loads(decoded)
        except Exception:
            print('Invalid JSON payload, dropping')
            return 'invalid', 200
        if isinstance(doc.get('findings'), list):
            findings = doc['findings']
        elif isinstance(doc.get('results'), list):
            findings = doc['results']
        elif isinstance(doc, dict):
            # Single finding wrapped directly
            findings = [doc]
        elif isinstance(doc, list):
            findings = doc

    # Resolve tenant via mapping/allowlist/pause
    resolved_tenant = _resolve_tenant(findings, default_tenant)
    if TENANT_ALLOWLIST and resolved_tenant not in TENANT_ALLOWLIST:
        print('Tenant not in allowlist; skipping batch:', resolved_tenant)
        return 'skipped_not_allowed', 200
    if resolved_tenant in TENANT_PAUSE_LIST:
        print('Tenant paused; skipping batch:', resolved_tenant)
        return 'paused', 200

    posture, assets = _build_payloads_from_findings(findings, resolved_tenant)

    idem = _calc_batch_id(posture)
    req_id = str(uuid.uuid4())
    headers = {'x-api-key': api_key, 'X-Idempotency-Key': idem, 'X-Request-ID': req_id}
    session = requests.Session()

    posture_status = None
    assets_status = None
    dlq_error: Optional[str] = None
    try:
        posture_status = _post_with_retries(session, base + '/api/v1/compliance/posture', headers, posture, DEFAULT_TIMEOUT)
        print('POST posture', posture_status)
    except Exception as e:
        dlq_error = f'POST posture failed: {e}'
        print(dlq_error)
    try:
        assets_status = _post_with_retries(session, base + '/api/v1/compliance/assets/sync', headers, assets, DEFAULT_TIMEOUT)
        print('POST assets', assets_status)
    except Exception as e:
        dlq_error = (dlq_error + '; ' if dlq_error else '') + f'POST assets failed: {e}'
        print(f'POST assets failed: {e}')

    ok_posture = posture_status is not None and 200 <= posture_status < 300
    ok_assets = assets_status is not None and 200 <= assets_status < 300

    if not (ok_posture and ok_assets):
        try:
            os.makedirs(os.path.dirname(DLQ_PATH), exist_ok=True)
            with open(DLQ_PATH, 'a', encoding='utf-8') as df:
                df.write(json.dumps({
                    'ts': int(time.time()),
                    'request_id': req_id,
                    'idempotency_key': idem,
                    'endpoint': base,
                    'posture_status': posture_status,
                    'assets_status': assets_status,
                    'error': dlq_error,
                    'payload': {'posture': posture, 'assets': assets}
                }) + '\n')
            print('Wrote DLQ line:', DLQ_PATH)
        except Exception as e:
            print('DLQ write failed:', e)
        return 'partial_failure', 200

    return 'ok', 200
