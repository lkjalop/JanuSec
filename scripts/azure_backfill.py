#!/usr/bin/env python3
"""
Azure Defender/Policy backfill helper
- Scans a directory tree for JSON exports
- Processes files grouped by mtime day (UTC) in daily chunks
- Posts posture and assets using the adapter
- Writes completion markers per day to avoid replays

Usage:
  python scripts/azure_backfill.py --dir C:\\ingest\\azure_defender --post https://platform.example --api-key <key> --tenant <tid>

Environment:
  DEV_ALLOW_HTTP=1           allow http:// for local dev
  PLATFORM_POST_TIMEOUT=10   request timeout seconds
  DLQ_PATH=./artifacts/dlq/azure_defender.jsonl
  BACKFILL_STATE_DIR=./artifacts/backfill/azure_defender
"""
from __future__ import annotations
import argparse, os, sys, json
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Tuple

# Reuse adapter functions
sys.path.append(str(Path(__file__).resolve().parents[1]))
from scripts.azure_defender_to_posture import build_payloads  # type: ignore
from scripts.azure_defender_to_posture import _tls_guard, _post_with_retry, _dlq_write  # type: ignore


def _utc_day(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%d')


def _post_payloads(base: str, api_key: str, tenant: str | None, posture: dict, assets: dict) -> Tuple[int, int]:
    headers = {'x-api-key': api_key, 'Content-Type': 'application/json'}
    if tenant:
        headers['X-Tenant-ID'] = tenant
    c1 = _post_with_retry(base.rstrip('/') + '/api/v1/compliance/posture', headers, posture, timeout=float(os.getenv('PLATFORM_POST_TIMEOUT','10') or 10.0))
    c2 = _post_with_retry(base.rstrip('/') + '/api/v1/compliance/assets/sync', headers, assets, timeout=float(os.getenv('PLATFORM_POST_TIMEOUT','10') or 10.0))
    return c1, c2


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dir', required=True, help='Directory containing Azure exports')
    ap.add_argument('--post', required=True, help='Platform base URL')
    ap.add_argument('--api-key', default=os.getenv('API_KEY','devkey123'))
    ap.add_argument('--tenant', default=os.getenv('TENANT_ID'))
    args = ap.parse_args()

    base = args.post
    if not _tls_guard(base):
        print('[!] TLS guard blocked egress; aborting.', file=sys.stderr)
        return 2

    root = Path(args.dir)
    if not root.exists():
        print(f'[!] Directory not found: {root}', file=sys.stderr)
        return 2

    state_dir = Path(os.getenv('BACKFILL_STATE_DIR', 'artifacts/backfill/azure_defender'))
    state_dir.mkdir(parents=True, exist_ok=True)

    # Group files by UTC day of mtime
    groups: dict[str, List[Path]] = {}
    for p in root.rglob('*.json'):
        try:
            day = _utc_day(p.stat().st_mtime)
        except Exception:
            day = _utc_day(0)
        groups.setdefault(day, []).append(p)

    exit_code = 0
    for day in sorted(groups.keys()):
        marker = state_dir / f'{day}.done'
        if marker.exists():
            continue
        files = sorted(groups[day])
        failed = 0
        for f in files:
            try:
                data = json.loads(f.read_text(encoding='utf-8'))
                posture, assets = build_payloads(data, args.tenant)
                c1, c2 = _post_payloads(base, args.api_key, args.tenant, posture, assets)
                if (c1 // 100) != 2 or (c2 // 100) != 2:
                    failed += 1
                    _dlq_write(os.getenv('DLQ_PATH', os.path.join(os.getcwd(), 'artifacts','dlq','azure_defender.jsonl')), posture.get('findings', []))
            except Exception as e:
                failed += 1
                print(f'[!] Failed for {f}: {e}', file=sys.stderr)
        if failed == 0:
            try:
                marker.write_text('ok')
            except Exception:
                pass
        else:
            exit_code = 1
            print(f'[!] Day {day} completed with {failed} errors', file=sys.stderr)
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())
