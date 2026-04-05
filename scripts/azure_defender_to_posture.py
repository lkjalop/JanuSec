#!/usr/bin/env python3
"""
Convert Azure Defender for Cloud / Azure Policy JSON exports into posture and assets payloads.

Usage:
  python scripts/azure_defender_to_posture.py --input export.json --post http://localhost:8080 --api-key devkey123 --tenant t1

If --post omitted, prints the JSON bodies for manual review.
"""
from __future__ import annotations
import argparse, json, os, sys
from typing import Any, Dict, List, Tuple
import time
import random
import hashlib
import hmac
import os


def _sev(v: str | None) -> str:
    s = (v or '').lower()
    if s in {'high','critical'}: return 'high'
    if s in {'medium','moderate'}: return 'medium'
    return 'low'


def build_payloads(doc: dict[str, Any], tenant: str | None) -> tuple[dict, dict]:
    posture_findings: List[dict] = []
    assets: List[dict] = []
    # Defender for Cloud exports often have 'value' array with recommendation/protectionResults
    items = []
    if isinstance(doc.get('value'), list):
        items = doc['value']
    elif isinstance(doc.get('results'), list):
        items = doc['results']

    for it in items:
        # Heuristic extraction
        props = it.get('properties') or {}
        disp = str(props.get('displayName') or it.get('displayName') or it.get('name') or '')
        sev = _sev(props.get('severity') or it.get('severity'))
        rid = (props.get('resourceDetails') or {}).get('id') or it.get('id') or ''
        rtype = ((props.get('resourceDetails') or {}).get('type') or '').lower()
        # Build assets
        if rid:
            assets.append({'id': str(rid), 'service': ('storage' if 'storage' in rid.lower() else ('network' if 'network' in rid.lower() else 'azure')), 'cloud': 'azure', 'tenant_id': tenant})
        # Map common misconfigs
        ftype = None
        title = disp.lower()
        if ('public access' in title or 'publicly accessible' in title) and ('storage' in title or 'blob' in title):
            ftype = 'cloud:public_bucket'
            sev = 'high'
        if ('network security group' in title or 'nsg' in title) and ('0.0.0.0/0' in title or 'open inbound' in title or 'any source' in title):
            ftype = 'cloud:sg_open_0_0_0_0'
        if ftype:
            posture_findings.append({'type': ftype, 'severity': sev, 'resource': rid or disp, 'service': 'azure', 'tenant_id': tenant})

    posture = {'findings': posture_findings, 'tenant_id': tenant}
    assets_payload = {'assets': assets}
    return posture, assets_payload


def _tls_guard(base: str) -> bool:
    if base.startswith('http://') and os.getenv('DEV_ALLOW_HTTP','0') not in {'1','true','yes','on'}:
        print(f'[!] Insecure API base {base}. Set DEV_ALLOW_HTTP=1 for local dev or use HTTPS.', file=sys.stderr)
        return False
    return True


def _post_with_retry(url: str, headers: dict, body: dict, timeout: float = 10.0, max_retries: int = 5, base_backoff: float = 0.6) -> int:
    import requests  # type: ignore
    last_code = 0
    for attempt in range(1, max_retries + 1):
        try:
            r = requests.post(url, headers=headers, json=body, timeout=timeout)
            last_code = r.status_code
            if r.status_code in {429,500,502,503,504}:
                raise RuntimeError(f'HTTP {r.status_code}')
            r.raise_for_status()
            return r.status_code
        except Exception as e:
            if attempt == max_retries:
                print(f'[!] POST failed after {attempt} attempts: {e}', file=sys.stderr)
                return last_code or 0
            time.sleep(min(8.0, base_backoff * (2 ** (attempt - 1)) + random.uniform(0,0.3)))


def _idem_key(tenant: str | None, findings: List[dict]) -> str:
    try:
        snapshot = json.dumps([{k:v for k,v in sorted(f.items()) if k in {'id','resource','type'}} for f in findings], separators=(',',':'))
    except Exception:
        snapshot = f'{len(findings)}:{time.time():.0f}'
    material = (tenant or '') + '|' + snapshot[:2000]
    return hmac.new(b'az_sched_idem', material.encode('utf-8'), hashlib.sha256).hexdigest()


def _dlq_write(path: str, records: List[dict]) -> None:
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'a', encoding='utf-8') as fh:
            for r in records:
                fh.write(json.dumps(r) + '\n')
    except Exception as e:
        print(f'[!] DLQ write failed: {e}', file=sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input', required=True)
    ap.add_argument('--post')
    ap.add_argument('--api-key', default=os.getenv('API_KEY','devkey123'))
    ap.add_argument('--tenant', default=os.getenv('TENANT_ID'))
    args = ap.parse_args()
    with open(args.input, 'r', encoding='utf-8') as f:
        doc = json.load(f)
    posture, assets = build_payloads(doc, args.tenant)
    if not args.post:
        print(json.dumps({'posture': posture, 'assets': assets}, indent=2))
        return
    try:
        import requests  # type: ignore
    except Exception:
        print('[!] requests not available; printing payloads instead:')
        print(json.dumps({'posture': posture, 'assets': assets}, indent=2))
        return
    base = args.post.rstrip('/')
    if not _tls_guard(base):
        print('[!] TLS guard blocked egress; writing to DLQ instead.', file=sys.stderr)
        _dlq_write(os.getenv('DLQ_PATH', os.path.join(os.getcwd(), 'artifacts','dlq','azure_defender.jsonl')), posture.get('findings', []))
        return
    headers = {'x-api-key': args.api_key, 'Content-Type': 'application/json'}
    if args.tenant:
        headers['X-Tenant-ID'] = args.tenant
    try:
        # Add idempotency key per file based on mtime + tenant
        try:
            mtime = os.path.getmtime(args.input)
        except Exception:
            mtime = time.time()
        idem = _idem_key(args.tenant, posture.get('findings', [])) + ':' + str(int(mtime))
        h1 = dict(headers)
        h1['X-Idempotency-Key'] = idem
        code = _post_with_retry(base + '/api/v1/compliance/posture', h1, posture, timeout=float(os.getenv('PLATFORM_POST_TIMEOUT','10') or 10.0))
        print('POST posture', code)
    except Exception as e:
        print('POST posture failed:', e)
        _dlq_write(os.getenv('DLQ_PATH', os.path.join(os.getcwd(), 'artifacts','dlq','azure_defender.jsonl')), posture.get('findings', []))
    try:
        code2 = _post_with_retry(base + '/api/v1/compliance/assets/sync', headers, assets, timeout=float(os.getenv('PLATFORM_POST_TIMEOUT','10') or 10.0))
        print('POST assets', code2)
    except Exception as e:
        print('POST assets failed:', e)


if __name__ == '__main__':
    main()

