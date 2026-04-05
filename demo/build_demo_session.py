#!/usr/bin/env python3
"""Automation helper: upload CSVs and build a multi-source HopGraph session."""
import os
import sys
import time
import json
from pathlib import Path
import requests

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = REPO_ROOT / 'demo' / 'datasets'
API_BASE = os.environ.get('DEMO_API_BASE', 'http://localhost:8080')
API_KEY = os.environ.get('DEMO_API_KEY')

HEADERS = {'x-api-key': API_KEY} if API_KEY else {}

FILES = [
    'endpoint_processes.csv',
    'network_dns.csv',
    'cloud_api_calls.csv',
    'email_phishing.csv',
    'data_store_access.csv',
    'api_gateway_logs.csv',
]


def wait_for_server(max_wait: int = 15) -> bool:
    """Poll a lightweight status endpoint until the server responds or timeout.

    Uses /status first (fast) then /api/v1/status/dashboard as fallback. Avoids
    failing uploads when the server is still initializing background tasks.
    """
    status_urls = [
        f"{API_BASE}/health",  # new lightweight endpoint
        f"{API_BASE}/status",
        f"{API_BASE}/api/v1/status/dashboard",
    ]
    start = time.time()
    while time.time() - start < max_wait:
        for url in status_urls:
            try:
                r = requests.get(url, headers=HEADERS, timeout=4)
                if r.status_code < 500:
                    return True
            except Exception:
                pass
        time.sleep(1)
    print(f"Server did not become ready within {max_wait}s at {API_BASE}")
    return False


def upload_file(path: Path) -> dict | None:
    url = f"{API_BASE}/api/v1/upload/files"
    with open(path, 'rb') as fh:
        # API expects field name 'files' (list[UploadFile]); send single-item list
        files = [('files', (path.name, fh, 'text/csv'))]
        try:
            upload_headers = {**HEADERS, 'X-Correlation-Analyze': 'true'}
            r = requests.post(url, headers=upload_headers, files=files, timeout=30)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            print(f"Upload failed for {path.name}: {e}")
            return None


def build_session(session_ids: list[str]) -> dict | None:
    url = f"{API_BASE}/api/v1/graph/session/build"
    payload = {
        'session_ids': session_ids,
        'correlate': True,
        'ewma': True,
        'ewma_alpha': 0.6,
        'include_llm': True,
        'mapping': {}
    }
    try:
        r = requests.post(url, headers={**HEADERS, 'Content-Type': 'application/json'}, json=payload, timeout=60)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"Session build failed: {e}")
        if hasattr(e, 'response') and e.response is not None:
            try:
                print(e.response.text)
            except Exception:
                pass
        return None


def main():
    print("Uploading demo files to:", API_BASE)
    if not wait_for_server():
        return 10
    session_ids = []
    for fname in FILES:
        path = DATA_DIR / fname
        if not path.exists():
            print("Missing file:", path)
            return 2
        res = upload_file(path)
        if not res:
            print("Failed to upload:", fname)
            return 3
        # Expect API to return a session id or file id
        sid = None
        # Single-session style keys
        sid = sid or res.get('session_id') or res.get('file_id') or res.get('id')
        # Multi-session list key
        if not sid and isinstance(res.get('session_ids'), list) and res.get('session_ids'):
            sid = res.get('session_ids')[0]
        if not sid:
            # Try to parse typical response shapes
            sid = res.get('uploaded') and res.get('uploaded')[0].get('session_id') if isinstance(res.get('uploaded'), list) else None
        if not sid and isinstance(res.get('results'), list) and res['results']:
            # Fallback: derive session id from sha256 of first processed file
            _sha = res['results'][0].get('sha256')
            if _sha:
                sid = _sha
        if sid:
            print(f"Uploaded {fname} -> session_id={sid}")
            session_ids.append(sid)
        else:
            print(f"Upload returned unexpected payload for {fname}: {json.dumps(res)[:200]}")
            return 4
        time.sleep(0.5)

    print("Building HopGraph session from uploaded IDs...")
    build = build_session(session_ids)
    if not build:
        print("Build failed")
        return 5

    out_path = REPO_ROOT / 'demo' / 'last_demo_session.json'
    out_path.write_text(json.dumps(build, indent=2))
    print("Build succeeded. Session saved to:", out_path)
    print("Top-level verdict:", build.get('summary', {}).get('verdict'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
