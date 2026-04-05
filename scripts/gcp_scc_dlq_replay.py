#!/usr/bin/env python3
import argparse
import json
import os
import time
import uuid
import requests


def main():
    ap = argparse.ArgumentParser(description='Replay GCP SCC DLQ JSONL lines to platform endpoints.')
    ap.add_argument('--dlq', required=True, help='Path to DLQ JSONL file')
    ap.add_argument('--post', required=True, help='Platform base URL')
    ap.add_argument('--api-key', default=os.getenv('API_KEY','devkey123'))
    ap.add_argument('--tenant', default=os.getenv('TENANT_ID'))
    ap.add_argument('--sleep-sec', type=float, default=0.2)
    args = ap.parse_args()

    base = args.post.rstrip('/')
    s = requests.Session()
    with open(args.dlq, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                rec = json.loads(line)
            except Exception:
                continue
            payload = rec.get('payload') or {}
            posture = payload.get('posture') or {'findings': [], 'tenant_id': args.tenant}
            assets = payload.get('assets') or {'assets': []}
            idem = str(uuid.uuid4())
            hdrs = {'x-api-key': args.api_key, 'X-Idempotency-Key': idem, 'X-Request-ID': str(uuid.uuid4())}
            # ensure tenant present
            if args.tenant and posture.get('tenant_id') is None:
                posture['tenant_id'] = args.tenant
            try:
                r1 = s.post(base + '/api/v1/compliance/posture', headers=hdrs, json=posture, timeout=10)
                print('posture', r1.status_code)
                r2 = s.post(base + '/api/v1/compliance/assets/sync', headers=hdrs, json=assets, timeout=10)
                print('assets', r2.status_code)
            except Exception as e:
                print('replay error:', e)
            time.sleep(args.sleep_sec)

if __name__ == '__main__':
    main()
