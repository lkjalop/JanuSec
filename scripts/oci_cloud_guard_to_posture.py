#!/usr/bin/env python3
"""
Convert Oracle Cloud (OCI) Cloud Guard problems export into posture and assets payloads.

Usage:
  python scripts/oci_cloud_guard_to_posture.py --input export.json --post http://localhost:8080 --api-key devkey123 --tenant t1

If --post omitted, prints the JSON bodies for manual review.
"""
from __future__ import annotations
import argparse, json, os, sys
from typing import Any, Dict, List


def build_payloads(doc: dict[str, Any], tenant: str | None) -> tuple[dict, dict]:
    posture_findings: List[dict] = []
    assets: List[dict] = []
    problems = []
    if isinstance(doc.get('problems'), list):
        problems = doc['problems']
    elif isinstance(doc.get('items'), list):
        problems = doc['items']

    for p in problems:
        title = str(p.get('title') or p.get('problemDescription') or '').lower()
        sev = str(p.get('riskLevel') or p.get('severity') or 'low').lower()
        rid = p.get('resourceName') or p.get('resourceId') or ''
        if rid:
            assets.append({'id': str(rid), 'service': 'oci', 'cloud': 'oci', 'tenant_id': tenant})
        ftype = None
        if 'public bucket' in title or ('object storage' in title and 'public' in title):
            ftype = 'cloud:public_bucket'; sev = 'high'
        if 'open to the internet' in title or '0.0.0.0/0' in title or 'anywhere' in title:
            ftype = 'cloud:sg_open_0_0_0_0'
        if ftype:
            posture_findings.append({'type': ftype, 'severity': sev, 'resource': rid or title, 'service': 'oci', 'tenant_id': tenant})

    posture = {'findings': posture_findings, 'tenant_id': tenant}
    assets_payload = {'assets': assets}
    return posture, assets_payload


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
    headers = {'x-api-key': args.api_key}
    try:
        r1 = requests.post(base + '/api/v1/compliance/posture', headers=headers, json=posture)
        print('POST posture', r1.status_code)
    except Exception as e:
        print('POST posture failed:', e)
    try:
        r2 = requests.post(base + '/api/v1/compliance/assets/sync', headers=headers, json=assets)
        print('POST assets', r2.status_code)
    except Exception as e:
        print('POST assets failed:', e)


if __name__ == '__main__':
    main()

