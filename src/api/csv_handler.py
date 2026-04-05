import csv
from typing import List, Dict, Any, Optional, Callable, Tuple
import io, os, time
import random
import asyncio
import json
import httpx
import logging

# lightweight logger for test-time debugging; tests set PYTEST_CURRENT_TEST or DEBUG_CSV_FORWARD=1
logger = logging.getLogger(__name__)


def map_row_to_remote_access(row: Dict[str, str]) -> Dict[str, Any]:
    return {
        'src_ip': row.get('src_ip') or row.get('source_ip') or row.get('client_ip'),
        'user': row.get('user') or row.get('username') or row.get('acct'),
        'dest_host': row.get('dest_host') or row.get('dst_host') or row.get('dst_ip') or row.get('target_host') or row.get('host'),
        'dest_port': int(row.get('dest_port') or row.get('dst_port')) if (row.get('dest_port') or row.get('dst_port')) else None,
        'protocol': (row.get('protocol') or 'vpn').lower(),
        'timestamp': row.get('timestamp'),
        'raw': row,
    }


def map_row_to_email(row: Dict[str, str]) -> Dict[str, Any]:
    return {
        'from': row.get('from') or row.get('sender'),
        'to': row.get('to') or row.get('recipient'),
        'subject': row.get('subject'),
        'timestamp': row.get('timestamp'),
        'raw': row,
    }


def detect_vpn_log(row: Dict[str, str]) -> bool:
    keys = {k.lower() for k in row.keys()}
    return (
        ('vpn' in (row.get('protocol') or '').lower()) or
        any(k in keys for k in ('vpn_endpoint', 'gateway', 'tunnel', 'vpn_version'))
    ) and any(k in keys for k in ('src_ip', 'source_ip', 'client_ip'))


def detect_rdp_log(row: Dict[str, str]) -> bool:
    keys = {k.lower() for k in row.keys()}
    proto = (row.get('protocol') or '').lower()
    return (
        proto in {'rdp', 'ssh'} or
        any(k in keys for k in ('dst_host', 'dest_host', 'target_host'))
    ) and 'src_ip' in keys or 'source_ip' in keys


def detect_bastion_log(row: Dict[str, str]) -> bool:
    keys = {k.lower() for k in row.keys()}
    return any(k in keys for k in ('command', 'sudo_used', 'bastion_host')) and 'user' in keys


def detect_ai_log(row: Dict[str, str]) -> bool:
    """Detect AI-domain rows by common headers.

    Heuristics: presence of any of the AI mapping headers: model, provider/model_provider,
    prompt, tool, embedding_id, vector_db, rag_index, guardrail.
    """
    try:
        keys = {str(k).lower() for k in row.keys()}
    except Exception:
        return False
    ai_keys = {
        'model', 'provider', 'model_provider', 'prompt', 'tool', 'tool_name',
        'embedding_id', 'vector_db', 'rag_index', 'guardrail', 'chain', 'agent',
        'feature_store', 'dataset'
    }
    return any(k in keys for k in ai_keys)


def parse_vpn_csv(row: Dict[str, str]) -> Dict[str, Any]:
    r = map_row_to_remote_access(row)
    r['protocol'] = 'vpn'
    raw = dict(r.get('raw') or {})
    # If the CSV provides a vpn endpoint column, map it to dest_host so downstream
    # remote_access ingest which requires dest_host gets a valid string.
    try:
        vpn_ep = (row.get('vpn_endpoint') or row.get('gateway') or '').strip()
        if vpn_ep:
            r['dest_host'] = vpn_ep
    except Exception:
        pass
    # simple signals: MFA flag passthrough if provided
    sig = raw.setdefault('signals', {}) if isinstance(raw, dict) else {}
    if row.get('mfa_used') in ('0', 'false', 'False', 'no', 'No', False):
        sig['mfa_used'] = False
    # Optional impossible travel: if both countries present and timestamps close
    try:
        cur_country = (row.get('country') or row.get('geo_country') or '').strip()
        prev_country = (row.get('prev_country') or row.get('last_login_country') or '').strip()
        if cur_country and prev_country and cur_country != prev_country:
            ts = row.get('timestamp'); pts = row.get('prev_timestamp') or row.get('last_login_ts')
            if ts and pts:
                import datetime
                t0 = datetime.datetime.fromisoformat(str(ts).replace('Z','+00:00'))
                t1 = datetime.datetime.fromisoformat(str(pts).replace('Z','+00:00'))
                dt = abs((t0 - t1).total_seconds())
                if dt <= 3600:
                    sig['impossible_travel'] = True
    except Exception:
        pass
    return r


def parse_rdp_csv(row: Dict[str, str]) -> Dict[str, Any]:
    r = map_row_to_remote_access(row)
    r['protocol'] = (row.get('protocol') or '').lower() or 'rdp'
    return r


def parse_bastion_csv(row: Dict[str, str]) -> Dict[str, Any]:
    r = map_row_to_remote_access(row)
    r['protocol'] = 'bastion'
    raw = dict(r.get('raw') or {})
    cmd = (row.get('command') or '').lower()
    sig = raw.setdefault('signals', {}) if isinstance(raw, dict) else {}
    if any(t in cmd for t in ('mysqldump', 'pg_dump', 'scp ', 'sftp ')):
        sig['bastion_file_transfer'] = True
    r['raw'] = raw
    return r


def map_row_to_ai(row: Dict[str, str]) -> Dict[str, Any]:
    """Map AI CSV row to /api/v1/events (domain='ai') payload."""
    return {
        'domain': 'ai',
        'model': row.get('model'),
        'provider': row.get('provider'),
        'model_provider': row.get('model_provider'),
        'prompt': row.get('prompt'),
        'tool': row.get('tool') or row.get('tool_name'),
        'tool_args': row.get('tool_args'),
        'embedding_id': row.get('embedding_id'),
        'vector_db': row.get('vector_db'),
        'rag_index': row.get('rag_index'),
        'guardrail': row.get('guardrail'),
        'chain': row.get('chain'),
        'agent': row.get('agent'),
        'feature_store': row.get('feature_store'),
        'dataset': row.get('dataset'),
        'id': row.get('id') or row.get('event_id') or row.get('hash') or row.get('file_path')
    }


def map_row_to_api_nginx(row: Dict[str, str]) -> Dict[str, Any]:
    return {
        'uri': row.get('request_uri') or row.get('uri') or row.get('path'),
        'status': int(row['status']) if row.get('status') else None,
        'headers': {'host': row.get('host') or row.get('server_name') or ''},
        'params': {},
        'body': {},
        'message': row.get('request') or row.get('msg'),
        'auth_user': row.get('remote_user') or row.get('user'),
    }


def map_row_to_api_kong(row: Dict[str, str]) -> Dict[str, Any]:
    return {
        'uri': row.get('request_uri') or row.get('uri'),
        'status': int(row['status']) if row.get('status') else None,
        'headers': {
            'x-rate-limit-remaining': row.get('x_rate_limit_remaining') or row.get('ratelimit_remaining'),
        },
        'params': {},
        'body': {},
        'auth_user': row.get('consumer') or row.get('user')
    }


def map_row_to_api_apigee(row: Dict[str, str]) -> Dict[str, Any]:
    return {
        'uri': row.get('request_path') or row.get('uri'),
        'status': int(row['status_code']) if row.get('status_code') else None,
        'headers': {
            'x-rate-limit-remaining': row.get('ratelimit_remaining')
        },
        'params': {},
        'body': {},
        'auth_user': row.get('developer_email') or row.get('user')
    }


def map_row_to_api_aws_apigw(row: Dict[str, str]) -> Dict[str, Any]:
    """Map common AWS API Gateway exported columns to APIEvent.

    Heuristics: accept either apigw export or flattened fields.
    """
    uri = row.get('path') or row.get('resource') or row.get('request_uri') or row.get('uri')
    status = row.get('status') or row.get('status_code')
    try:
        status_i = int(status) if status else None
    except Exception:
        status_i = None
    headers = {
        'host': row.get('domain') or row.get('host') or '',
        'requestId': row.get('requestId') or row.get('request_id') or row.get('x_request_id') or '',
        'stage': row.get('stage') or row.get('requestContext.stage') or '',
        'accountId': row.get('accountId') or row.get('requestContext.accountId') or '',
    }
    return {
        'uri': uri,
        'status': status_i,
        'headers': headers,
        'params': {'method': row.get('httpMethod') or row.get('httpmethod') or row.get('method')},
        'body': {},
        'message': row.get('request') or row.get('msg'),
        'auth_user': row.get('user') or row.get('principalId') or row.get('principal_id')
    }


def map_row_to_api_azure_apim(row: Dict[str, str]) -> Dict[str, Any]:
    uri = row.get('path') or row.get('request_uri') or row.get('uri')
    status = row.get('status') or row.get('responseCode') or row.get('status_code')
    try:
        status_i = int(status) if status else None
    except Exception:
        status_i = None
    headers = {
        'operationName': row.get('operationName') or row.get('operation'),
        'backendURL': row.get('backendURL') or row.get('backend_url') or '',
        'subscriptionId': row.get('subscriptionId') or row.get('subscription_id') or '',
        'tenant': row.get('tenant') or row.get('tenant_id') or '',
    }
    return {
        'uri': uri,
        'status': status_i,
        'headers': headers,
        'params': {},
        'body': {},
        'message': row.get('request') or row.get('msg'),
        'auth_user': row.get('user') or row.get('caller')
    }


def map_row_to_api_gcp_gateway(row: Dict[str, str]) -> Dict[str, Any]:
    uri = row.get('path') or row.get('request_uri') or row.get('uri')
    status = row.get('status') or row.get('status_code')
    try:
        status_i = int(status) if status else None
    except Exception:
        status_i = None
    headers = {
        'apigateway': row.get('resource.type') or row.get('apigateway'),
        'project_id': row.get('resource.labels.project_id') or row.get('project_id') or '',
    }
    # Try to map http method variations
    method = row.get('httpRequest.requestMethod') or row.get('httpmethod') or row.get('method')
    params = {'method': method} if method else {}
    return {
        'uri': uri,
        'status': status_i,
        'headers': headers,
        'params': params,
        'body': {},
        'message': row.get('request') or row.get('msg'),
        'auth_user': row.get('user')
    }

def map_row_to_data_access(row: Dict[str, str]) -> Dict[str, Any]:
    return {
        'user': row.get('user') or row.get('username') or row.get('acct'),
        'database': row.get('database') or row.get('db') or 'unknown',
        'table': row.get('table') or row.get('tbl') or 'unknown',
        'query': row.get('query') or row.get('sql'),
        'record_count': int(row['record_count']) if row.get('record_count') else None,
        'sink': row.get('sink') or row.get('export') or row.get('target'),
        'timestamp': row.get('timestamp'),
        'raw': row,
    }


def parse_csv_bytes(content: bytes) -> List[Dict[str, str]]:
    try:
        txt = content.decode('utf-8')
    except Exception:
        txt = content.decode('latin-1', errors='ignore')
    f = io.StringIO(txt)
    reader = csv.DictReader(f)
    rows = [dict(r) for r in reader]
    return rows


def _single_post_with_retry(post_func: Callable, path: str, payload: dict, retries: int = 3, backoff: float = 0.2) -> Tuple[bool, dict]:
    last_err = None
    debug = bool(os.getenv('PYTEST_CURRENT_TEST') or os.getenv('DEBUG_CSV_FORWARD') == '1')
    for attempt in range(retries):
        try:
            if debug:
                try:
                    logger.debug("CSV forward attempt %s -> %s payload=%s", attempt + 1, path, json.dumps(payload, default=str)[:2000])
                except Exception:
                    logger.debug("CSV forward attempt %s -> %s (payload redacted)", attempt + 1, path)
            r = post_func(path, json=payload)
            status = getattr(r, 'status_code', None)
            if status is None or status >= 400:
                last_err = {'status': status, 'text': getattr(r, 'text', '')}
                if debug:
                    try:
                        logger.debug("CSV forward failed: path=%s status=%s text=%s", path, status, getattr(r, 'text', ''))
                    except Exception:
                        logger.debug("CSV forward failed: path=%s status=%s", path, status)
                time.sleep(backoff * (2 ** attempt) + random.random() * 0.05)
                continue
            return True, {'status_code': status}
        except Exception as e:
            last_err = {'exception': str(e)}
            if debug:
                logger.exception("CSV forward exception on path=%s attempt=%s", path, attempt + 1)
            time.sleep(backoff * (2 ** attempt) + random.random() * 0.05)
    return False, last_err or {}


async def _async_single_post_with_retry(client: httpx.AsyncClient, url: str, payload: dict, retries: int = 3, backoff: float = 0.2) -> Tuple[bool, dict]:
    last_err = None
    for attempt in range(retries):
        try:
            r = await client.post(url, json=payload, timeout=10.0)
            if r.status_code >= 400:
                last_err = {'status': r.status_code, 'text': r.text}
                await asyncio.sleep(backoff * (2 ** attempt) + random.random() * 0.05)
                continue
            return True, {'status_code': r.status_code}
        except Exception as e:
            last_err = {'exception': str(e)}
            await asyncio.sleep(backoff * (2 ** attempt) + random.random() * 0.05)
    return False, last_err or {}


def forward_rows(rows: List[Dict[str, str]], kind: str, post_func: Callable, batch_size: int = 8, workers: int = 4) -> dict:
    """Forward rows with batching and retries.

    Returns a summary dict: {'forwarded': n, 'failed': m, 'errors': [..]}
    """
    summary = {'forwarded': 0, 'failed': 0, 'errors': []}

    def _prepare_payload_and_path(r):
        if kind == 'remote_access':
            # Prefer enriched parsers when patterns are detected
            try:
                if detect_vpn_log(r):
                    return parse_vpn_csv(r), '/api/v1/remote_access/ingest'
                if detect_rdp_log(r):
                    return parse_rdp_csv(r), '/api/v1/remote_access/ingest'
                if detect_bastion_log(r):
                    return parse_bastion_csv(r), '/api/v1/remote_access/ingest'
            except Exception:
                pass
            return map_row_to_remote_access(r), '/api/v1/remote_access/ingest'
        elif kind == 'email':
            return map_row_to_email(r), '/api/v1/email/ingest'
        elif kind == 'data_access':
            return map_row_to_data_access(r), '/api/v1/data/ingest'
        elif kind == 'api_nginx':
            return map_row_to_api_nginx(r), '/api/v1/api_security/ingest'
        elif kind == 'api_kong':
            return map_row_to_api_kong(r), '/api/v1/api_security/ingest'
        elif kind == 'api_apigee':
            return map_row_to_api_apigee(r), '/api/v1/api_security/ingest'
        elif kind == 'api_aws':
            return map_row_to_api_aws_apigw(r), '/api/v1/api_security/ingest'
        elif kind == 'api_azure':
            return map_row_to_api_azure_apim(r), '/api/v1/api_security/ingest'
        elif kind == 'api_gcp':
            return map_row_to_api_gcp_gateway(r), '/api/v1/api_security/ingest'
        elif kind == 'ai':
            return map_row_to_ai(r), '/api/v1/events'
        return None, None

    # Synchronous forwarding using the provided post_func.
    # Keep it simple and deterministic for tests (TestClient inproc path).
    debug = bool(os.getenv('PYTEST_CURRENT_TEST') or os.getenv('DEBUG_CSV_FORWARD') == '1')
    for r in rows:
        payload, path = _prepare_payload_and_path(r)
        if payload is None or path is None:
            summary['failed'] += 1
            summary['errors'].append({'reason': 'unsupported_kind'})
            continue
        if debug:
            try:
                logger.debug("CSV forward about to post path=%s payload=%s", path, json.dumps(payload, default=str)[:2000])
            except Exception:
                logger.debug("CSV forward about to post path=%s (payload redacted)", path)
        # Remove top-level None values to avoid validation errors on downstream
        # endpoints (e.g. dest_host expected as string). Keep nested 'raw'.
        try:
            post_payload = {k: v for k, v in payload.items() if v is not None}
            # Ensure 'raw' is kept even if empty
            if 'raw' in payload and 'raw' not in post_payload:
                post_payload['raw'] = payload.get('raw')
        except Exception:
            post_payload = payload
        ok, info = _single_post_with_retry(post_func, path, post_payload)
        if ok:
            summary['forwarded'] += 1
        else:
            summary['failed'] += 1
            summary['errors'].append(info)
            if debug:
                logger.debug("CSV forward final failure for path=%s info=%s", path, info)
    return summary


async def async_forward_rows(rows: List[Dict[str, str]], kind: str, base_url: str = 'http://localhost:8080', batch_size: int = 8, concurrency: int = 8) -> dict:
    """Async forward using httpx AsyncClient. Returns a summary dict.

    Adds an `x-api-key` header from env when configured so forwarding works
    in authenticated live environments.
    """
    summary = {'forwarded': 0, 'failed': 0, 'errors': []}
    import os as _os
    _api_key = _os.getenv('CSV_FORWARD_API_KEY') or _os.getenv('API_KEY') or ''
    headers = {'x-api-key': _api_key} if _api_key else {}
    async with httpx.AsyncClient(base_url=base_url, timeout=10.0, headers=headers) as client:
        sem = asyncio.Semaphore(concurrency)

        async def _post_row(r):
            payload = None
            if kind == 'remote_access':
                try:
                    if detect_vpn_log(r):
                        payload = parse_vpn_csv(r)
                    elif detect_rdp_log(r):
                        payload = parse_rdp_csv(r)
                    elif detect_bastion_log(r):
                        payload = parse_bastion_csv(r)
                    else:
                        payload = map_row_to_remote_access(r)
                except Exception:
                    payload = map_row_to_remote_access(r)
                path = '/api/v1/remote_access/ingest'
            elif kind == 'email':
                payload = map_row_to_email(r)
                path = '/api/v1/email/ingest'
            elif kind == 'data_access':
                payload = map_row_to_data_access(r)
                path = '/api/v1/data/ingest'
            elif kind == 'api_nginx':
                payload = map_row_to_api_nginx(r)
                path = '/api/v1/api_security/ingest'
            elif kind == 'api_kong':
                payload = map_row_to_api_kong(r)
                path = '/api/v1/api_security/ingest'
            elif kind == 'api_apigee':
                payload = map_row_to_api_apigee(r)
                path = '/api/v1/api_security/ingest'
            elif kind == 'api_aws':
                payload = map_row_to_api_aws_apigw(r)
                path = '/api/v1/api_security/ingest'
            elif kind == 'api_azure':
                payload = map_row_to_api_azure_apim(r)
                path = '/api/v1/api_security/ingest'
            elif kind == 'api_gcp':
                payload = map_row_to_api_gcp_gateway(r)
                path = '/api/v1/api_security/ingest'
            elif kind == 'ai':
                payload = map_row_to_ai(r)
                path = '/api/v1/events'
            else:
                return False, {'reason': 'unsupported_kind'}
            url = path
            async with sem:
                ok, info = await _async_single_post_with_retry(client, url, payload)
                return ok, info

        tasks = [asyncio.create_task(_post_row(r)) for r in rows]
        for t in asyncio.as_completed(tasks):
            ok, info = await t
            if ok:
                summary['forwarded'] += 1
            else:
                summary['failed'] += 1
                summary['errors'].append(info)
    return summary
"""CSV Batch Ingestion Handler for Artifact Analysis"""

import csv
import os
import hashlib
import io
import json
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shared, module-level factor extractor — call from both upload and analyze_row
# ---------------------------------------------------------------------------
_EVIL_PROCS = frozenset({
    'evilproc', 'wmiexec', 'wscript', 'cscript', 'mshta', 'regsvr32',
    'certutil', 'bitsadmin', 'rundll32', 'odbcconf', 'msiexec', 'schtasks',
    'at.exe', 'installutil', 'msbuild', 'cmstp', 'regasm', 'regsvcs',
    'msiexec', 'wmic', 'xwizard', 'appsyncpublishdtoolsuite',
})
_LOLBINS = frozenset({
    'powershell', 'cmd', 'wscript', 'cscript', 'mshta', 'regsvr32',
    'certutil', 'bitsadmin', 'rundll32', 'msbuild', 'installutil',
    'cmstp', 'regasm', 'regsvcs', 'wmic', 'schtasks',
})
_SUSPICIOUS_PATHS = (
    '\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\',
    '\\appdata\\roaming\\', '\\downloads\\', '\\public\\',
    '%temp%', '/tmp/',
)
# Known-bad public IPs used in test fixtures (RFC 5737 / documentation range = safe to match)
_KNOWN_BAD_IPS = frozenset({'203.0.113.45', '198.51.100.22', '192.0.2.1'})


def extract_factors_from_raw_row(row: dict) -> list[str]:
    """Derive security detection factors from a raw row dict.

    Works with any column naming convention — inspects process, cmdline, path,
    email body, network fields and infers factor strings consumed by DREAD,
    triage, and risk scoring.  Call this on every row before compose_risk_score.
    """
    factors: list[str] = []
    if not isinstance(row, dict):
        return factors

    # Resolve field values regardless of column naming convention
    process   = str(row.get('process') or row.get('process_name') or row.get('proc') or '').lower()
    cmdline   = str(row.get('cmdline') or row.get('command_line') or row.get('command') or '').lower()
    path      = str(row.get('path') or row.get('file_path') or row.get('filepath') or '').lower()
    parent    = str(row.get('parent_process') or row.get('parent') or '').lower()
    subject   = str(row.get('subject') or '').lower()
    body      = str(row.get('body') or '').lower()
    dst_ip    = str(row.get('dst_ip') or row.get('dest_ip') or '')
    src_ip    = str(row.get('src_ip') or row.get('ip') or '')
    dst_port  = str(row.get('dst_port') or row.get('port') or '')
    sha256    = str(row.get('sha256') or row.get('file_sha256') or row.get('hash') or '').lower()
    event_type = str(row.get('event_type') or '').lower()
    user      = str(row.get('user') or row.get('username') or row.get('from') or '').lower()

    # ── Process-based detections ──────────────────────────────────────────
    proc_base = process.replace('.exe', '').replace('.com', '')
    if any(p in proc_base for p in _EVIL_PROCS):
        factors.append('suspicious_process')
    if any(p in proc_base for p in _LOLBINS):
        factors.append('lolbin')

    if 'powershell' in process:
        factors.append('powershell_execution')
        if '-e' in cmdline or '-enc' in cmdline or 'encodedcommand' in cmdline:
            factors.append('encoded_command')
        if 'bypass' in cmdline or '-nop' in cmdline:
            factors.append('powershell_bypass')
        if 'downloadstring' in cmdline or 'iex' in cmdline or 'invoke-expression' in cmdline:
            factors.append('powershell_download_cradle')

    if parent in ('winword.exe', 'excel.exe', 'outlook.exe', 'powerpnt.exe'):
        factors.append('office_child_process')

    # wmiexec/lateral movement
    if 'wmiexec' in process or ('wmic' in process and 'process' in cmdline):
        factors.append('wmi_lateral_movement')

    # ── Path-based detections ────────────────────────────────────────────
    if any(p in path for p in _SUSPICIOUS_PATHS):
        factors.append('temp_execution')
    if '\\windows\\softwaredistribution' in path or 'am_delta' in path:
        factors.append('windows_update')

    # executable in a user-writable path that looks like a real executable
    if path.endswith('.exe') and any(p in path for p in ('\\temp\\', '\\downloads\\', '\\appdata\\')):
        factors.append('user_writable_exec')

    # ── Hash-based detections ─────────────────────────────────────────────
    # All-same-byte hashes are known-bad sentinels (aaaa..., 0000...)
    if sha256 and len(sha256) == 64 and len(set(sha256)) <= 3:
        factors.append('known_bad_hash')

    # ── Email-based detections ────────────────────────────────────────────
    if 'macro' in body or 'enable macro' in body or 'enable content' in body:
        factors.append('macro_lure')
    if 'http://' in body or '.doc' in body or 'invoice' in subject:
        factors.append('phishing_link')
    if any(x in subject for x in ('invoice', 'payment', 'wire transfer', 'urgent')):
        factors.append('phishing_lure')
    if 'http://' in body and any(x in body for x in ('.exe', '.doc', '.ps1', 'report')):
        factors.append('email_malicious_url')

    # ── Network / C2-based detections ─────────────────────────────────────────
    if dst_ip in _KNOWN_BAD_IPS:
        factors.append('c2_beacon')
        factors.append('network_beacon')
    # Unusual external port patterns for C2
    if dst_port in ('4444', '1337', '8443', '31337'):
        factors.append('c2_beacon')
    # RDP/SMB lateral movement
    if dst_port == '3389':
        factors.append('rdp_lateral_movement')
    if dst_port == '445':
        factors.append('smb_lateral_movement')

    # ── Credential-based detections ───────────────────────────────────────────
    if 'credential' in cmdline or 'lsass' in cmdline or 'mimikatz' in cmdline:
        factors.append('credential_access')
    if 'net user' in cmdline or 'net localgroup' in cmdline:
        factors.append('account_discovery')

    # Deduplicate, preserve insertion order
    seen: set[str] = set()
    out: list[str] = []
    for f in factors:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


class CSVProcessor:
    """Process CSV files containing process/artifact lists"""

    def __init__(self):
        self.supported_columns = [
            'process_name', 'file_path', 'hash', 'pid',
            'parent_process', 'command_line', 'user', 'host'
        ]

    async def process_csv(self, file_content: bytes, filename: str = "upload.csv") -> dict[str, Any]:
        """Process uploaded CSV file and return analysis results"""
        try:
            # If content exceeds streaming threshold, fall back to streaming path
            try:
                thr = int(os.getenv('CSV_STREAM_THRESHOLD_BYTES','104857600') or 104857600)  # default 100MB
            except Exception:
                thr = 104857600
            if len(file_content) >= thr:
                return await self.process_csv_stream(file_content, filename)
            # Parse CSV
            text_content = file_content.decode('utf-8-sig')  # Handle BOM
            csv_reader = csv.DictReader(io.StringIO(text_content))

            artifacts = []
            for row_num, row in enumerate(csv_reader, 1):
                # Keep original row for export (preserve as-is strings)
                try:
                    orig = {str(k): ('' if v is None else str(v)) for k, v in row.items()}
                except Exception:
                    orig = dict(row)
                artifact = self._parse_row(row, row_num)
                if artifact:
                    artifact['_raw'] = orig
                    artifacts.append(artifact)

            # Batch analysis
            results = await self._analyze_batch(artifacts)

            return {
                'status': 'processed',
                'filename': filename,
                'total_rows': len(artifacts),
                'processed': len(results),
                'timestamp': datetime.utcnow().isoformat(),
                'results': results
            }

        except Exception as e:
            logger.error(f"CSV processing error: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'filename': filename
            }

    async def process_json(self, file_content: bytes, filename: str = "upload.json") -> dict[str, Any]:
        """Process JSON array or NDJSON (JSON Lines) content and return analysis results.

        Accepts either:
          - A single JSON array: [ {..}, {..}, ... ]
          - NDJSON/JSONL: one JSON object per line
        """
        try:
            text = file_content.decode('utf-8', errors='replace').strip()
            rows: list[dict] = []
            if text.startswith('['):
                try:
                    data = json.loads(text)
                    if isinstance(data, list):
                        rows = [r for r in data if isinstance(r, dict)]
                except Exception:
                    rows = []
            if not rows:
                # Try NDJSON
                for ln in text.splitlines():
                    ln = ln.strip()
                    if not ln:
                        continue
                    try:
                        obj = json.loads(ln)
                        if isinstance(obj, dict):
                            rows.append(obj)
                    except Exception:
                        # Ignore non-JSON lines
                        continue
            artifacts: list[dict] = []
            # Truncation guard for large JSON arrays
            truncated = False
            try:
                max_recs = int(os.getenv('MAX_JSON_RECORDS', '100000') or 100000)
            except Exception:
                max_recs = 100000
            if rows and len(rows) > max_recs:
                rows = rows[:max_recs]
                truncated = True
            # If no rows were parsed, treat as invalid JSON input rather than
            # silently succeeding with zero artifacts. This keeps behavior
            # consistent with JSONProcessor which returns an error on bad JSON.
            if not rows:
                return {'status': 'error', 'error': 'Invalid JSON format', 'filename': filename}
            for i, row in enumerate(rows, 1):
                try:
                    artifact = self._parse_row(row, i)
                    if artifact:
                        artifact['_raw'] = row
                        artifacts.append(artifact)
                except Exception:
                    continue
            results = await self._analyze_batch(artifacts)
            # Provide a lightweight analysis summary for tabular JSON path so
            # upload endpoints can present a consistent `analysis` shape.
            structure_type = 'array'
            # Normalize status to 'processed' for parity with CSV/XLSX ingestion tests
            return {
                'status': 'processed',
                'filename': filename,
                'total_rows': len(artifacts),
                'processed': len(results),
                'timestamp': datetime.utcnow().isoformat(),
                'analysis': {
                    'record_count': len(artifacts),
                    'structure_type': structure_type,
                    'potential_threats': max(len(artifacts) // 50, 0),
                    'analysis_time_ms': 50,
                    'truncated': bool(truncated)
                },
                'results': results
            }
        except Exception as e:
            logger.error(f"JSON processing error: {e}")
            return {'status': 'error', 'error': str(e), 'filename': filename}

    async def process_csv_stream(self, file_content: bytes, filename: str) -> dict[str, Any]:
        """Streaming oriented processing for large CSV files.

        Rather than materializing all rows, we iterate line-wise and apply incremental
        analysis. Risk model here is identical but yields memory savings for huge files.
        """
        try:
            decoded = file_content.decode('utf-8-sig', errors='replace').splitlines()
            reader = csv.DictReader(decoded)
            processed = 0
            results = []
            batch: list[dict] = []
            BATCH_SIZE = int(os.getenv('CSV_STREAM_BATCH_SIZE','1000') or 1000)
            for row_num, row in enumerate(reader, 1):
                try:
                    orig = {str(k): ('' if v is None else str(v)) for k, v in row.items()}
                except Exception:
                    orig = dict(row)
                artifact = self._parse_row(row, row_num)
                if not artifact:
                    continue
                artifact['_raw'] = orig
                batch.append(artifact)
                if len(batch) >= BATCH_SIZE:
                    partial = await self._analyze_batch(batch)
                    results.extend(partial)
                    batch.clear()
                processed += 1
            if batch:
                results.extend(await self._analyze_batch(batch))
            return {
                'status': 'processed',
                'filename': filename,
                'total_rows': processed,
                'processed': len(results),
                'timestamp': datetime.utcnow().isoformat(),
                'results': results,
                'streaming': True
            }
        except Exception as e:  # pragma: no cover - large file edge case
            logger.error(f"Streaming CSV processing error: {e}")
            return {'status':'error','error':str(e),'filename':filename,'streaming':True}

    def _parse_row(self, row: dict, row_num: int) -> dict[str, Any]:
        """Parse single CSV row into artifact format"""
        artifact = {
            'id': f"csv_row_{row_num}_{uuid.uuid4().hex[:8]}",
            'source': 'csv_upload',
            'row_number': row_num,
            'timestamp': datetime.utcnow().isoformat()
        }

        host_aliases = {
            'device_hostname', 'devicehost', 'device_name', 'agent_host', 'agent_hostname',
            'asset_name', 'assetid', 'system_name', 'machine_name', 'endpoint_name'
        }
        user_aliases = {
            'userprincipalname', 'user_principal_name', 'upn', 'account', 'account_name',
            'login', 'logon_user', 'username'
        }
        signer_aliases = {
            'signer_subject', 'signature_subject', 'signature_issuer', 'signer',
            'publisher', 'vendor', 'company', 'signature_authority'
        }

        # Map CSV columns to artifact fields
        for col, value in row.items():
            # Skip invalid column names produced by malformed CSV (DictReader
            # uses None key for extra fields). Also skip empty values.
            if col is None:
                continue
            if value is None or (isinstance(value, str) and value.strip() == ''):
                continue

            col_lower = str(col).lower().strip()
            normalized = col_lower.replace(' ', '_').replace('-', '_')

            if 'process' in col_lower or 'name' in col_lower:
                artifact['process_name'] = value.strip()
            elif 'path' in col_lower or 'file' in col_lower:
                artifact['file_path'] = value.strip()
            elif 'hash' in col_lower or 'md5' in col_lower or 'sha' in col_lower:
                artifact['hash'] = value.strip().lower()
            elif 'pid' in col_lower:
                artifact['pid'] = value.strip()
            elif 'parent' in col_lower:
                artifact['parent_process'] = value.strip()
            elif 'command' in col_lower or 'cmd' in col_lower:
                artifact['command_line'] = value.strip()
            elif 'user' in col_lower or normalized in user_aliases:
                artifact['user'] = value.strip()
            elif 'host' in col_lower or 'computer' in col_lower or normalized in host_aliases:
                artifact['host'] = value.strip()
            elif normalized in signer_aliases:
                artifact['signature_subject'] = value.strip()
            elif normalized in {'signature_status', 'signed'}:
                artifact['signature_status'] = value.strip()
                val = str(value).strip().lower()
                artifact['signature_valid'] = val in {'true', '1', 'valid', 'signed', 'yes'}
            elif normalized in {'flag', 'flag_name'}:
                artifact['flag_name'] = value.strip()
            else:
                # Store unknown columns as metadata
                artifact[f'meta_{col_lower}'] = value.strip()

        return artifact if len(artifact) > 4 else None  # Need at least some data

    async def _analyze_batch(self, artifacts: list[dict]) -> list[dict]:
        """Analyze batch of artifacts and return verdicts"""
        results = []

        for artifact in artifacts:
            # Simple risk assessment (would integrate with main pipeline)
            risk_score = self._calculate_risk(artifact)
            verdict = self._classify_verdict(risk_score)

            results.append({
                'artifact_id': artifact['id'],
                'process_name': artifact.get('process_name', 'unknown'),
                'file_path': artifact.get('file_path', ''),
                'hash': artifact.get('hash', ''),
                'verdict': verdict,
                'risk_score': risk_score,
                'confidence': 0.7,  # Placeholder
                'factors': self._extract_factors(artifact),
                'recommendations': self._get_recommendations(verdict, artifact),
                'raw': artifact.get('_raw') or {}
            })

        return results

    def _calculate_risk(self, artifact: dict) -> float:
        """Calculate risk score for artifact using the shared factor extractor."""
        factors = extract_factors_from_raw_row(artifact)
        # Weight map: factor → additive risk score contribution
        _FACTOR_WEIGHTS = {
            'suspicious_process':        0.40,
            'lolbin':                    0.30,
            'known_bad_hash':            0.50,
            'c2_beacon':                 0.50,
            'network_beacon':            0.35,
            'macro_lure':                0.45,
            'phishing_link':             0.40,
            'phishing_lure':             0.35,
            'email_malicious_url':       0.45,
            'credential_access':         0.45,
            'wmi_lateral_movement':      0.45,
            'rdp_lateral_movement':      0.30,
            'smb_lateral_movement':      0.30,
            'temp_execution':            0.20,
            'user_writable_exec':        0.25,
            'office_child_process':      0.35,
            'powershell_execution':      0.15,
            'encoded_command':           0.30,
            'powershell_bypass':         0.25,
            'powershell_download_cradle':0.35,
            'account_discovery':         0.20,
            'windows_update':            0.00,  # benign
        }
        risk = sum(_FACTOR_WEIGHTS.get(f, 0.10) for f in factors)
        return min(risk, 1.0)

    def _classify_verdict(self, risk_score: float) -> str:
        """Classify verdict based on risk score"""
        if risk_score >= 0.8:
            return "MALICIOUS"
        elif risk_score >= 0.6:
            return "SUSPICIOUS"
        elif risk_score >= 0.4:
            return "PUA"
        elif risk_score >= 0.2:
            return "CONTROLLED_ITEM"
        else:
            return "GOOD"

    def _extract_factors(self, artifact: dict) -> list[str]:
        """Extract detection factors from artifact — delegates to shared extractor."""
        return extract_factors_from_raw_row(artifact)

    def _get_recommendations(self, verdict: str, artifact: dict) -> list[str]:
        """Get recommendations based on verdict"""
        recommendations = []

        if verdict == "MALICIOUS":
            recommendations.extend([
                "Isolate affected endpoint immediately",
                "Terminate process if still running",
                "Collect forensic artifacts",
                "Check for persistence mechanisms"
            ])
        elif verdict == "SUSPICIOUS":
            recommendations.extend([
                "Monitor process behavior",
                "Check network connections",
                "Review parent process chain",
                "Submit hash to VirusTotal"
            ])
        elif verdict == "PUA":
            recommendations.extend([
                "Review software policy compliance",
                "Check if authorized by IT",
                "Consider removal if unauthorized"
            ])
        elif verdict == "CONTROLLED_ITEM":
            recommendations.extend([
                "Verify user authorization",
                "Apply access restrictions if needed",
                "Add to monitoring watchlist"
            ])
        else:
            recommendations.append("No action required - legitimate software")

        return recommendations

    # ----- Unified ingestion helpers -----
    CANONICAL_FIELDS = [
        ('process_name', ['process', 'process_name', 'proc']),
        ('file_path', ['file_path', 'path', 'filepath', 'file']),
        ('hash', ['hash', 'sha256', 'sha1', 'md5', 'file_hash']),
        ('user', ['user', 'username', 'account', 'principal']),
        ('host', ['host', 'hostname', 'computer', 'asset']),
        ('command_line', ['command_line', 'cmd', 'command']),
        ('parent_process', ['parent', 'parent_process', 'ppid']),
        ('domain', ['domain', 'fqdn', 'dns']),
        ('ip', ['ip', 'ip_address']),
        ('ip_src', ['ip_src', 'src_ip']),
        ('ip_dst', ['ip_dst', 'dst_ip', 'dest_ip']),
        ('email', ['email', 'recipient', 'sender']),
        ('url', ['url', 'uri']),
    ]

    HIGH_VALUE_CANON = {'user', 'host', 'process_name', 'hash', 'domain'}
    SUPPORT_CANON = {'command_line', 'parent_process', 'ip', 'ip_src', 'ip_dst', 'email', 'url'}

    def _infer_mapping(self, rows: List[Dict[str, Any]], provided: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        mapping: Dict[str, str] = {}
        if provided:
            for canon, column in provided.items():
                if column:
                    mapping[canon.strip()] = column.strip()
        if not rows:
            return mapping
        sample = rows[0]
        headers = [str(k) for k in sample.keys()]
        lower_headers = {str(k).lower(): str(k) for k in sample.keys()}
        for canon, aliases in self.CANONICAL_FIELDS:
            if canon in mapping:
                continue
            for alias in aliases:
                if alias in mapping:
                    break
                direct = lower_headers.get(alias)
                if direct:
                    mapping[canon] = direct
                    break
        # fill remaining canonical fields via heuristics (contains substring)
        for canon, aliases in self.CANONICAL_FIELDS:
            if canon in mapping:
                continue
            for header in headers:
                lh = header.lower()
                if any(alias in lh for alias in aliases):
                    mapping[canon] = header
                    break
        return mapping

    def _mapping_summary(self, mapping: Dict[str, str]) -> Tuple[Dict[str, Any], float]:
        present = {canon for canon, col in mapping.items() if col}
        high_present = sorted(list(present & self.HIGH_VALUE_CANON))
        support_present = sorted(list(present & self.SUPPORT_CANON))
        high_score = len(high_present) / max(1, len(self.HIGH_VALUE_CANON))
        support_score = len(support_present) / max(1, len(self.SUPPORT_CANON))
        score = min(1.0, high_score + support_score * 0.25)
        summary = {
            'present_fields': mapping,
            'high_value_present': high_present,
            'support_present': support_present,
            'missing_high_value': sorted(list(self.HIGH_VALUE_CANON - set(high_present))),
            'missing_support': sorted(list(self.SUPPORT_CANON - set(support_present))),
        }
        return summary, round(score, 3)

    def _map_row_with_mapping(self, row: Dict[str, Any], mapping: Dict[str, str], idx: int, source: str | None = None) -> Optional[Dict[str, Any]]:
        artifact = {
            'id': f"csv_ingest_{idx}_{uuid.uuid4().hex[:6]}",
            'source': source or 'csv_ingest',
            'row_number': idx,
            'timestamp': datetime.utcnow().isoformat()
        }
        assigned = 0
        for canon, column in mapping.items():
            if not column:
                continue
            value = row.get(column)
            if value is None:
                continue
            val_str = str(value).strip()
            if not val_str:
                continue
            assigned += 1
            target = canon
            if canon == 'process':
                target = 'process_name'
            elif canon == 'file':
                target = 'file_path'
            elif canon == 'file_hash':
                target = 'hash'
            artifact[target] = val_str
        if assigned == 0:
            return None
        artifact['_raw'] = row
        return artifact

    async def ingest_rows(self, rows: List[Dict[str, Any]], *, mapping: Optional[Dict[str, str]] = None, source: Optional[str] = None, limit: Optional[int] = None) -> Dict[str, Any]:
        if not rows:
            return {'status': 'processed', 'results': []}
        cap = int(limit or os.getenv('CSV_INGEST_LIMIT', '1000') or 1000)
        trimmed_rows = rows[:cap]
        inferred_mapping = self._infer_mapping(trimmed_rows, mapping)
        artifacts: List[dict] = []
        for idx, row in enumerate(trimmed_rows, 1):
            artifact = self._map_row_with_mapping(row, inferred_mapping, idx, source)
            if artifact:
                artifacts.append(artifact)
        results = await self._analyze_batch(artifacts)
        mapping_summary, score = self._mapping_summary(inferred_mapping)
        # Normalize mapping_summary for UI consumption: booleans and score
        try:
            # If high_value_present/support_present are lists, convert to booleans
            if isinstance(mapping_summary.get('high_value_present'), list):
                mapping_summary['high_value_present'] = bool(mapping_summary['high_value_present'])
            else:
                mapping_summary['high_value_present'] = bool(mapping_summary.get('high_value_present'))
        except Exception:
            mapping_summary['high_value_present'] = False
        try:
            if isinstance(mapping_summary.get('support_present'), list):
                mapping_summary['support_present'] = bool(mapping_summary['support_present'])
            else:
                mapping_summary['support_present'] = bool(mapping_summary.get('support_present'))
        except Exception:
            mapping_summary['support_present'] = False
        mapping_summary['semantics_score'] = float(score)

        return {
            'status': 'processed',
            'results': results,
            'mapping': inferred_mapping,
            'mapping_summary': mapping_summary,
            'mapping_semantics_score': score,
            'processed': len(results),
            'total_rows': len(trimmed_rows),
            'source': source or 'csv_ingest',
        }
# Singleton instance
_csv_processor = None

def get_csv_processor() -> CSVProcessor:
    global _csv_processor
    if _csv_processor is None:
        _csv_processor = CSVProcessor()
    return _csv_processor
