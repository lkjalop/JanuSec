#!/usr/bin/env python3
"""
Convert Google Cloud SCC (Security Command Center) JSON exports into posture and assets payloads.

Usage:
    python scripts/gcp_scc_to_posture.py --input export.json --post http://localhost:8080 --api-key devkey123 --tenant t1

If --post omitted, prints the JSON bodies for manual review.

Production hardening:
- Retries with exponential backoff + jitter
- Idempotency header derived from stable finding fields
- Request timeout and TLS guard (optional)
- DLQ JSONL write on terminal failure
- Maps SCC eventTime to posture finding source_ts (for lag metrics)
"""
from __future__ import annotations
import argparse, json, os, sys, time, uuid, hashlib, random
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_TIMEOUT = 8
MAX_RETRIES = 4
BACKOFF_BASE = 0.35


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


def build_payloads(doc: Dict[str, Any], tenant: Optional[str]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    posture_findings: List[Dict[str, Any]] = []
    assets: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    # SCC often uses top-level 'findings' or 'results'
    if isinstance(doc.get('findings'), list):
        findings = doc['findings']
    elif isinstance(doc.get('results'), list):
        findings = doc['results']

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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input', required=True)
    ap.add_argument('--post', help='Platform base URL (e.g. https://your.platform)')
    ap.add_argument('--api-key', default=os.getenv('API_KEY','devkey123'))
    ap.add_argument('--tenant', default=os.getenv('TENANT_ID'))
    ap.add_argument('--dlq-path', default=os.getenv('GCP_SCC_DLQ_PATH', 'data/dlq/gcp_scc.jsonl'))
    ap.add_argument('--tls-enforce', default=os.getenv('TLS_ENFORCE','0'))
    ap.add_argument('--timeout', type=int, default=int(os.getenv('HTTP_TIMEOUT', str(DEFAULT_TIMEOUT))))
    ap.add_argument('--tenant-mapping-json', default=os.getenv('TENANT_MAPPING_JSON'))
    ap.add_argument('--tenant-allowlist', default=os.getenv('TENANT_ALLOWLIST'))
    ap.add_argument('--tenant-pause-list', default=os.getenv('TENANT_PAUSE_LIST'))
    ap.add_argument('--last-ok-path', default=os.getenv('GCP_SCC_LAST_OK_PATH','data/sessions/gcp_scc_last_ok.txt'))
    args = ap.parse_args()
    with open(args.input, 'r', encoding='utf-8') as f:
        doc = json.load(f)
    # Tenant mapping resolution by project id (first match wins)
    def _extract_project_id(resource_name: str) -> Optional[str]:
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

    resolved_tenant = args.tenant
    try:
        mapping = {}
        if args.tenant_mapping_json:
            with open(args.tenant_mapping_json, 'r', encoding='utf-8') as mf:
                mapping = json.load(mf)
        projects = mapping.get('projects') if isinstance(mapping, dict) else {}
        default_tenant = mapping.get('default_tenant') if isinstance(mapping, dict) else None
        # Try to infer from input doc
        f_list = doc.get('findings') or doc.get('results') or []
        if isinstance(f_list, list):
            for f in f_list:
                rn = _norm_str(f.get('resourceName') or f.get('resource'))
                pid = _extract_project_id(rn) if rn else None
                if pid and projects and pid in projects:
                    resolved_tenant = projects.get(pid)
                    break
        if not resolved_tenant:
            resolved_tenant = default_tenant or args.tenant
    except Exception:
        resolved_tenant = args.tenant

    # Allowlist/pause controls
    allow = set([t.strip() for t in (args.tenant_allowlist.split(',') if args.tenant_allowlist else []) if t.strip()])
    pause = set([t.strip() for t in (args.tenant_pause_list.split(',') if args.tenant_pause_list else []) if t.strip()])
    if allow and resolved_tenant not in allow:
        print('[i] tenant not allowlisted; skipping:', resolved_tenant)
        return
    if resolved_tenant in pause:
        print('[i] tenant paused; skipping:', resolved_tenant)
        return

    posture, assets = build_payloads(doc, resolved_tenant)
    if not args.post:
        print(json.dumps({'posture': posture, 'assets': assets}, indent=2))
        return
    try:
        import requests  # type: ignore
    except Exception:
        print('[!] requests not available; printing payloads instead:')
        print(json.dumps({'posture': posture, 'assets': assets}, indent=2))
        return
    base = str(args.post).rstrip('/')
    if args.tls_enforce and args.tls_enforce not in ('0','false','False','no','NO'):
        if not base.startswith('https://'):
            print('[!] TLS_ENFORCE is enabled; refusing non-HTTPS endpoint:', base)
            return

    os.makedirs(os.path.dirname(args.dlq_path), exist_ok=True)

    # Build stable idempotency key per batch
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

    idem = _calc_batch_id(posture)
    req_id = str(uuid.uuid4())
    headers = {'x-api-key': args.api_key, 'X-Idempotency-Key': idem, 'X-Request-ID': req_id}

    session = requests.Session()

    def _post_with_retries(path: str, payload: Dict[str, Any]) -> int:
        url = base + path
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                r = session.post(url, headers=headers, json=payload, timeout=args.timeout)
                if r.status_code >= 200 and r.status_code < 300:
                    return r.status_code
                # retry on 5xx or 409/429
                if r.status_code in (409, 429) or 500 <= r.status_code < 600:
                    raise RuntimeError(f'HTTP {r.status_code}')
                # non-retryable
                return r.status_code
            except Exception as e:  # pragma: no cover (network)
                if attempt == MAX_RETRIES:
                    raise
                backoff = BACKOFF_BASE * (2 ** (attempt - 1)) + random.uniform(0, 0.2)
                time.sleep(backoff)
        return 0

    posture_status = None
    assets_status = None
    dlq_error: Optional[str] = None
    try:
        posture_status = _post_with_retries('/api/v1/compliance/posture', posture)
        print('POST posture', posture_status)
    except Exception as e:
        dlq_error = f'POST posture failed: {e}'
        print(dlq_error)
    try:
        assets_status = _post_with_retries('/api/v1/compliance/assets/sync', assets)
        print('POST assets', assets_status)
    except Exception as e:
        dlq_error = (dlq_error + '; ' if dlq_error else '') + f'POST assets failed: {e}'
        print(f'POST assets failed: {e}')

    # DLQ on terminal failure or non-2xx for either
    success = (posture_status is not None and 200 <= posture_status < 300) and (assets_status is not None and 200 <= assets_status < 300)
    if not success:
        with open(args.dlq_path, 'a', encoding='utf-8') as df:
            df.write(json.dumps({
                'ts': int(time.time()),
                'request_id': req_id,
                'idempotency_key': idem,
                'endpoint': base,
                'posture_status': posture_status,
                'assets_status': assets_status,
                'error': dlq_error,
                'payload': {
                    'posture': posture,
                    'assets': assets,
                }
            }) + '\n')
        print('[!] Wrote to DLQ:', args.dlq_path)
    else:
        # Update last_ok for backend dependency banner if path is set
        try:
            os.makedirs(os.path.dirname(args.last_ok_path), exist_ok=True)
            with open(args.last_ok_path, 'w', encoding='utf-8') as lf:
                lf.write(str(int(time.time())))
        except Exception as e:
            print('[i] last_ok write failed:', e)


if __name__ == '__main__':
    main()

