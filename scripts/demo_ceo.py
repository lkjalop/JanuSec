"""CEO Demo Script: Simulated Streaming via CSV Multi Upload

Usage:
  python -m scripts.demo_ceo --api http://localhost:8080 \
    tests/fixtures/api_gateway_sample.csv \
    tests/fixtures/database_query_sample.csv \
    tests/fixtures/vpn_access_sample.csv \
    tests/fixtures/rdp_sessions_sample.csv

Sends each CSV to /api/v1/csv_multi/upload, one per second, with x-api-key.
"""
import argparse
import time
import requests
import sys
from pathlib import Path


def post_csv(api: str, file_path: Path, api_key: str) -> dict:
    with file_path.open('rb') as f:
        files = {'file': (file_path.name, f, 'text/csv')}
        r = requests.post(f"{api}/api/v1/csv_multi/upload", files=files, headers={'x-api-key': api_key})
    try:
        return {'status_code': r.status_code, 'json': r.json()}
    except Exception:
        return {'status_code': getattr(r, 'status_code', 0), 'json': {}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('csvs', nargs='+', help='CSV files to upload, in order')
    ap.add_argument('--api', default='http://localhost:8080')
    ap.add_argument('--api-key', default='devkey123')
    ap.add_argument('--delay', type=float, default=1.0)
    args = ap.parse_args()
    for p in args.csvs:
        fp = Path(p)
        if not fp.exists():
            print(f"skip missing {fp}")
            continue
        res = post_csv(args.api, fp, args.api_key)
        print(f"upload {fp.name} -> {res['status_code']}")
        time.sleep(max(0.1, args.delay))


if __name__ == '__main__':
    sys.exit(main())

