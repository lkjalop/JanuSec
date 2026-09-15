"""Bounded authenticated read-load sample; never a production capacity certificate."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import statistics
import time

import requests


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--credential', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--seconds', type=int, default=300)
    parser.add_argument('--clients', type=int, default=4)
    parser.add_argument('--interval', type=float, default=1.0,
                        help='Pause per client between reads; default stays below the 300/minute guard')
    parser.add_argument('--port', type=int, default=8445)
    args = parser.parse_args()
    if not 1 <= args.clients <= 8 or not 1 <= args.seconds <= 3600 or not 0.05 <= args.interval <= 30:
        parser.error('use 1..8 clients and 1..3600 seconds')
    credential = json.loads(args.credential.read_text(encoding='utf-8'))
    baseline = json.loads(args.baseline.read_text(encoding='utf-8'))
    started = time.monotonic()
    def client(_):
        session = requests.Session(); session.trust_env = False
        session.verify = str(args.state / 'tls-cert.pem')
        session.headers.update({'x-api-key': credential['key'], 'x-tenant-id': credential['tenant_id']})
        samples, errors = [], []
        paths = [f"/api/v1/assessments/{baseline['assessment_id']}/progress",
                 f"/api/v1/assessments/{baseline['assessment_id']}/evidence"]
        while time.monotonic() - started < args.seconds:
            begin = time.monotonic()
            try:
                response = session.get('https://127.0.0.1:' + str(args.port) + paths[len(samples) % 2], timeout=30)
                if response.status_code != 200:
                    errors.append({'status': response.status_code})
                else:
                    response.json()
            except (requests.RequestException, ValueError) as exc:
                errors.append({'type': type(exc).__name__})
            samples.append(time.monotonic() - begin)
            time.sleep(args.interval)
        session.close()
        return samples, errors
    with ThreadPoolExecutor(max_workers=args.clients) as pool:
        all_results = list(pool.map(client, range(args.clients)))
    samples = sorted(value for values, _ in all_results for value in values)
    errors = [error for _, values in all_results for error in values]
    result = {'clients': args.clients, 'interval_seconds': args.interval,
              'duration_seconds': round(time.monotonic() - started, 2),
              'requests': len(samples), 'errors': len(errors), 'error_examples': errors[:10],
              'throttled_requests': sum(error.get('status') == 429 for error in errors),
              'latency_scope': 'all responses, including any rejections',
              'p50_seconds': round(statistics.median(samples), 3),
              'p95_seconds': round(samples[min(len(samples) - 1, int(len(samples) * .95))], 3),
              'max_seconds': round(max(samples), 3), 'live_provider': False,
              'production_capacity_certified': False, 'passed': not errors}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result))
    if errors:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
