#!/usr/bin/env python3
import argparse
import json
import os
import time
import subprocess
from pathlib import Path


def main():
    ap = argparse.ArgumentParser(description='Backfill GCP SCC exports via adapter with completion markers and throttling.')
    ap.add_argument('--exports-dir', required=True)
    ap.add_argument('--post', required=True)
    ap.add_argument('--api-key', default=os.getenv('API_KEY','devkey123'))
    ap.add_argument('--tenant', default=os.getenv('TENANT_ID'))
    ap.add_argument('--sleep-sec', type=float, default=float(os.getenv('BACKFILL_SLEEP_SEC','0.3')))
    args = ap.parse_args()

    exports = Path(args.exports_dir)
    done_dir = exports / '.done'
    done_dir.mkdir(parents=True, exist_ok=True)

    adapter = 'scripts/gcp_scc_to_posture.py'
    for p in sorted(exports.glob('*.json')):
        marker = done_dir / (p.name + '.ok')
        if marker.exists():
            continue
        env = os.environ.copy()
        env['TENANT_ID'] = args.tenant or ''
        cmd = ['python', adapter, '--input', str(p), '--post', args.post, '--api-key', args.api_key]
        print('Backfill:', p)
        rc = subprocess.call(cmd, env=env)
        if rc == 0:
            marker.write_text(str(int(time.time())))
        else:
            print('Failed:', p, 'rc=', rc)
        time.sleep(args.sleep_sec)

if __name__ == '__main__':
    main()
