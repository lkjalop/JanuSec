#!/usr/bin/env python3
"""
Convert AWS Config / Security Hub style JSON exports into posture and assets payloads.

Usage:
  python scripts/aws_config_to_posture.py --input config.json --post http://localhost:8080 --api-key devkey123 --tenant t1

If --post omitted, prints the JSON bodies for manual review.
"""
from __future__ import annotations
import argparse, json, sys, os
from typing import Any, Dict, List

def build_payloads(doc: dict[str, Any], tenant: str | None) -> tuple[dict, dict]:
    posture_findings: List[dict] = []
    assets: List[dict] = []
    # Try to normalize common shapes: Security Hub Findings or Config Rules evaluations
    findings = []
    if isinstance(doc.get('Findings'), list):
        findings = doc['Findings']
    elif isinstance(doc.get('results'), list):
        findings = doc['results']
    # Very lightweight heuristics
    for f in findings:
        title = str(f.get('Title') or f.get('title') or '')
        res = f.get('Resources') or f.get('resources') or []
        sev = (f.get('Severity') or f.get('severity') or {}).get('Label') if isinstance(f.get('Severity') or f.get('severity'), dict) else (f.get('Severity') or f.get('severity'))
        sev = (str(sev) or 'LOW').lower()
        service = 's3' if 's3' in title.lower() else ('iam' if 'iam' in title.lower() else '')
        # map a couple of common cases
        ftype = None
        if 'public' in title.lower() and 'bucket' in title.lower():
            ftype = 'cloud:public_bucket'; sev = 'high'
        if 'unencrypted' in title.lower() and 's3' in title.lower():
            ftype = 'cloud:s3_no_encryption'
        # assets
        for r in res:
            rid = r.get('Id') or r.get('id') or r.get('ResourceId') or r.get('resourceId')
            if rid:
                assets.append({'id': str(rid), 'service': service or (r.get('Type') or r.get('type') or '').lower(), 'cloud': 'aws', 'tenant_id': tenant})
        if ftype:
            posture_findings.append({'type': ftype, 'severity': sev, 'resource': (res[0].get('Id') if res else None), 'service': service, 'tenant_id': tenant})
    posture = {'findings': posture_findings, 'tenant_id': tenant}
    assets_payload = {'assets': assets}
    return posture, assets_payload

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input', required=True, help='AWS Config / Security Hub JSON export')
    ap.add_argument('--post', help='Base URL to POST to (e.g., http://localhost:8080)')
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
        print('[!] requests not available; printing payloads instead:', file=sys.stderr)
        print(json.dumps({'posture': posture, 'assets': assets}, indent=2))
        return
    base = args.post.rstrip('/')
    headers = {'x-api-key': args.api_key}
    r1 = requests.post(base + '/api/v1/compliance/posture', headers=headers, json=posture)
    print('POST posture', r1.status_code)
    r2 = requests.post(base + '/api/v1/compliance/assets/sync', headers=headers, json=assets)
    print('POST assets', r2.status_code)

if __name__ == '__main__':
    main()

