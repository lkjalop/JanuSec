#!/usr/bin/env python3
"""
Ingest a few rows from bundled samples to show parity after seeding.

Usage:
  python scripts/ingest_small_sample.py --api http://localhost:8080 --key devkey123
"""
import argparse, csv, json, sys

try:
    import requests
except Exception:
    print("ERROR: requests not installed. pip install requests", file=sys.stderr)
    sys.exit(1)


def post_csv_rows(api, headers, path, kind):
    with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
        r = csv.DictReader(fh)
        rows = []
        for i, row in enumerate(r):
            rows.append(row)
            if i >= 9:
                break
    # Use csv_multi/upload to leverage existing mapping logic
    files = {'file': ('sample.csv', open(path, 'rb'), 'text/csv')}
    data = {'mapping': json.dumps({})}
    try:
        requests.post(f"{api}/api/v1/csv_multi/upload", headers=headers, files=files, data=data, timeout=10)
    except Exception:
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--api', default='http://localhost:8080')
    ap.add_argument('--key', default='devkey123')
    ap.add_argument('--tenant', default=None)
    args = ap.parse_args()
    headers = {'x-api-key': args.key}
    if args.tenant:
        headers['X-Tenant-ID'] = args.tenant

    post_csv_rows(args.api, headers, 'samples/batch/network_flows.csv', 'network')
    post_csv_rows(args.api, headers, 'tests/data/sample_email_bec.csv', 'email')
    post_csv_rows(args.api, headers, 'tests/data/sample_remote_access.csv', 'remote_access')
    print('Posted small sample batches.')


if __name__ == '__main__':
    main()

