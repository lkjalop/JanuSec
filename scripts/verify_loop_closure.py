"""Loop-closure regression harness.

Requirements: backend running at http://localhost:8080. Set TEST_HELPERS_ENABLED=1
to enable test-mode behavior (avoids real webhooks).

What this script does:
1. POST /api/v1/csv/deep_analyze with a tiny payload.
2. Start auto backfill and poll status.
3. Fetch the parent assessment and print the new playbook_preview/evidence_summary fields.
4. Ping /api/v1/graph/session/stream (SSE) to ensure HopGraph overlays are streaming.
5. Enumerate any available test hooks (incidents/SBOM captures).

Usage:
  python scripts/verify_loop_closure.py --server http://localhost:8080
"""

import argparse
import json
import time
from typing import Any
import requests


def _print_banner(msg: str) -> None:
    print("\n" + "=" * 80)
    print(msg)
    print("=" * 80)


def post_deep_analyze(base: str, api_key: str) -> dict:
    url = f"{base}/api/v1/csv/deep_analyze"
    payload = {
        "rows": [
            {"process_name": "notepad.exe", "file_path": "C:/Windows/notepad.exe", "sha256": ""},
            {"process_name": "powershell.exe", "file_path": "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "sha256": ""}
        ],
        "org": "unknown"
    }
    headers = {'Content-Type': 'application/json', 'x-api-key': api_key}
    r = requests.post(url, json=payload, headers=headers, timeout=20)
    r.raise_for_status()
    return r.json()


def start_backfill(base: str, assessment_id: str, api_key: str) -> dict:
    url = f"{base}/api/v1/csv/deep_analyze/auto_backfill"
    payload = {"assessment_id": assessment_id, "target_coverage": 1.0, "batch_size": 10}
    headers = {'Content-Type': 'application/json', 'x-api-key': api_key}
    r = requests.post(url, json=payload, headers=headers, timeout=10)
    r.raise_for_status()
    return r.json()


def poll_backfill(base: str, assessment_id: str, api_key: str, timeout: int = 120) -> dict:
    status_url = f"{base}/api/v1/csv/deep_analyze/auto_backfill/{assessment_id}/status"
    headers = {'x-api-key': api_key}
    start = time.time()
    last = None
    while True:
        r = requests.get(status_url, headers=headers, timeout=10)
        if r.status_code == 200:
            last = r.json()
            print('status:', last.get('status'), 'processed:', last.get('processed'), 'total:', last.get('total'), 'coverage:', last.get('coverage'))
            if last.get('status') in ('completed', 'cancelled') or (last.get('coverage') or 0) >= 1.0:
                return last
        else:
            print('status fetch failed', r.status_code, r.text)
        if time.time() - start > timeout:
            raise TimeoutError('backfill polling timed out')
        time.sleep(2)


def capture_test_hooks(base: str) -> dict:
    """Attempt to capture outbound webhook/sbom/incident captures using available test helpers.

    Returns a dict with any captured artifacts found by invoking common test helper endpoints.
    """
    out = {}
    # Try cert_checks.force_flush_for_tests if available
    try:
        r = requests.post(f"{base}/api/v1/test/force_flush_cert_checks", timeout=5)
        if r.ok:
            out['cert_checks_flush'] = r.json()
    except Exception:
        pass
    # Try integrations cert_checks force flush via known internal helper (fallback to manual probe)
    try:
        r = requests.get(f"{base}/api/v1/sbom/recent", timeout=5)
        if r.ok:
            out['sbom_recent'] = r.json()
    except Exception:
        pass
    # Try to hit a test-only endpoint that reports captured webhook attempts if present
    try:
        r = requests.get(f"{base}/api/v1/test/webhook_capture", timeout=5)
        if r.ok:
            out['webhook_capture'] = r.json()
    except Exception:
        pass
    return out


def fetch_assessment(base: str, assessment_id: str, api_key: str) -> dict:
    """Load assessment payload to inspect new enrichment fields."""
    url = f"{base}/api/v1/assessments/{assessment_id}"
    headers = {'x-api-key': api_key}
    r = requests.get(url, headers=headers, timeout=20)
    r.raise_for_status()
    return r.json()


def summarize_assessment(data: dict) -> None:
    status = data.get('status')
    coverage = data.get('evidence_summary') or {}
    pb = data.get('playbook_preview') or {}
    print('assessment status:', status, '| rows_processed:', data.get('rows_processed'))
    if coverage:
        print('evidence coverage:', json.dumps(coverage, indent=2))
    else:
        print('evidence coverage: <missing>')
    if pb:
        print('playbook preview:', json.dumps({k: pb.get(k) for k in ('domain', 'summary', 'steps')}, indent=2))
    else:
        print('playbook preview: <missing>')
    rows = data.get('llm_rows') or data.get('rows') or []
    if rows:
        sample = rows[0]
        print('sample row summary:', json.dumps({
            'row_index': sample.get('row_index'),
            'verdict': sample.get('verdict'),
            'evidence_summary': sample.get('evidence_summary'),
            'playbook_preview': sample.get('playbook_preview'),
        }, indent=2))
    else:
        print('no llm_rows found on assessment')


def ping_hopgraph_stream(base: str, api_key: str, wait_seconds: int = 8, tenant: str | None = None) -> None:
    """Connect to the HopGraph SSE stream and print the next event payload if available."""
    url = f"{base}/api/v1/graph/session/stream"
    headers = {
        'Accept': 'text/event-stream',
        'x-api-key': api_key,
    }
    if tenant:
        headers['X-Tenant-ID'] = tenant
    print(f'Connecting to {url} (waiting up to {wait_seconds}s for data)...')
    try:
        with requests.get(url, headers=headers, stream=True, timeout=wait_seconds + 2) as resp:
            resp.raise_for_status()
            started = time.time()
            for raw in resp.iter_lines(decode_unicode=True):
                if raw is None:
                    continue
                raw = raw.strip()
                if not raw:
                    continue
                if raw.startswith(':'):
                    continue  # keepalive
                if raw.startswith('data:'):
                    payload = raw[5:].strip()
                    try:
                        data = json.loads(payload)
                    except Exception:
                        data = payload
                    print('hopgraph stream sample event:', data)
                    return
                if time.time() - started > wait_seconds:
                    break
        print('HopGraph stream connected but no event received (try after more sessions?).')
    except Exception as exc:
        print(f'HopGraph stream check failed: {exc}')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--server', default='http://localhost:8080')
    p.add_argument('--api-key', default='devkey123')
    p.add_argument('--tenant', default=None, help='Optional tenant header for the SSE stream')
    p.add_argument('--timeout', type=int, default=180)
    args = p.parse_args()
    base = args.server.rstrip('/')
    api_key = args.api_key

    _print_banner('Step 1: Create assessment via /api/v1/csv/deep_analyze')
    resp = post_deep_analyze(base, api_key)
    print('create response keys:', list(resp.keys()))
    # Look for assessment id in several places
    aid = resp.get('assessment_id') or resp.get('report_id') or resp.get('assessment') or None
    if not aid:
        # Some responses return nested objects
        if isinstance(resp, dict):
            for v in resp.values():
                if isinstance(v, dict) and v.get('assessment_id'):
                    aid = v.get('assessment_id')
                    break
    if not aid:
        print('Failed to determine assessment_id from response:', resp)
        return
    print('Assessment created:', aid)

    _print_banner('Step 2: Start auto backfill and poll status')
    start_backfill(base, aid, api_key)
    print('Polling backfill status...')
    status = poll_backfill(base, aid, api_key, timeout=args.timeout)
    print('Final status snapshot:', json.dumps(status, indent=2))

    _print_banner('Step 3: Inspect assessment playbook/evidence context')
    assessment = fetch_assessment(base, aid, api_key)
    summarize_assessment(assessment)

    _print_banner('Step 4: Ping HopGraph SSE stream')
    if args.tenant:
        # temporarily inject tenant header by monkeypatching requests default headers via session
        requests_session = requests.Session()
        requests_session.headers.update({'X-Tenant-ID': args.tenant})
    ping_hopgraph_stream(base, api_key, tenant=args.tenant)

    _print_banner('Step 5: Probe loop-closure test hooks')
    caps = capture_test_hooks(base)
    print('Captured hooks:', json.dumps(caps, indent=2))
    print('Done')


if __name__ == '__main__':
    main()
