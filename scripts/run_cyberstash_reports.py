#!/usr/bin/env python3
"""
CyberStash Excel → All-Persona Report Generator
================================================
Processes both CyberStash Excel files through the JanuSec pipeline and
generates reports for every persona:
  - executive
  - soc_analyst  (SOC Analyst)
  - threat_hunter (Threat Hunter)
  - forensics

Reports are saved to:  dump/reports/cyberstash_<file>_<persona>.html

Usage:
    python scripts/run_cyberstash_reports.py [--server http://localhost:8090]
"""
from __future__ import annotations

import argparse
import io
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'src'))

DUMP = ROOT / 'dump'
OUT_DIR = DUMP / 'reports'
OUT_DIR.mkdir(parents=True, exist_ok=True)

HEADERS = {
    'x-api-key': 'devkey123',
    'X-Tenant-ID': 'default',
}

FILES = [
    DUMP / 'cybstash csv1.xlsx',
    DUMP / 'Cyberstash_csv2.xlsx',
]

PERSONAS = ['executive', 'soc_analyst', 'threat_hunter', 'forensics']

# ---------------------------------------------------------------------------

def upload_excel(server: str, filepath: Path) -> dict:
    """Upload an Excel file via /api/v1/csv/upload (multipart, field='file')."""
    import urllib.request
    boundary = 'JanuSecBoundary1234567890'
    with open(filepath, 'rb') as f:
        file_bytes = f.read()
    filename = filepath.name
    body = (
        f'--{boundary}\r\n'
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        'Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\r\n'
        '\r\n'
    ).encode() + file_bytes + f'\r\n--{boundary}--\r\n'.encode()

    req = urllib.request.Request(
        f'{server}/api/v1/csv/upload',
        data=body,
        method='POST',
        headers={
            **HEADERS,
            'Content-Type': f'multipart/form-data; boundary={boundary}',
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode(errors='replace')
        print(f"  [WARN] Upload HTTP {e.code}: {body_text[:300]}")
        return {'error': f'HTTP {e.code}', 'detail': body_text[:300]}


def fetch_recent_sessions(server: str) -> list:
    """Get recently ingested session IDs."""
    import urllib.request
    req = urllib.request.Request(
        f'{server}/api/v1/decisions/recent?limit=5',
        headers=HEADERS,
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            return data if isinstance(data, list) else data.get('items', [])
    except Exception as e:
        print(f"  [WARN] Could not fetch recent sessions: {e}")
        return []


def generate_report(server: str, session_id: str, persona: str) -> dict | None:
    """Call the ingestion report endpoint for a specific persona."""
    import urllib.request
    url = (
        f'{server}/api/v1/report/ingestion'
        f'?format=json&include_model=true&include_scenarios=true'
        f'&persona={persona}&session_ids={session_id}'
    )
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode(errors='replace')
        print(f"  [WARN] Report HTTP {e.code} for persona={persona}: {body_text[:200]}")
        return None
    except Exception as e:
        print(f"  [WARN] Report failed for persona={persona}: {e}")
        return None


def generate_html_report(server: str, session_id: str, persona: str) -> str | None:
    """Call the HTML report endpoint."""
    import urllib.request
    url = (
        f'{server}/api/v1/report/ingestion'
        f'?format=html&include_model=true&include_scenarios=true'
        f'&persona={persona}&session_ids={session_id}'
    )
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.read().decode(errors='replace')
    except urllib.error.HTTPError as e:
        body_text = e.read().decode(errors='replace')
        print(f"  [WARN] HTML report HTTP {e.code} for persona={persona}: {body_text[:200]}")
        return None
    except Exception as e:
        print(f"  [WARN] HTML report failed: {e}")
        return None


def ingest_csv_directly(server: str, filepath: Path) -> str | None:
    """For CSV1 (single-column path list), build a synthetic upload payload."""
    import urllib.request
    import pandas as pd

    df = pd.read_excel(filepath)
    # Convert path list to endpoint events
    rows = []
    for i, row in df.iterrows():
        path = str(row.get('path', '')).strip()
        if not path:
            continue
        ext = Path(path).suffix.lower()
        process = Path(path).name
        # Annotate suspicious items
        suspicious_markers = ['temp', 'appdata', 'programdata', 'users\\public', 'users/public']
        suspicious_exes = ['powershell', 'cmd', 'wscript', 'cscript', 'mshta', 'regsvr32', 'rundll32']
        is_sus_path = any(m in path.lower() for m in suspicious_markers)
        is_sus_proc = any(s in process.lower() for s in suspicious_exes)
        rows.append({
            'source_kind': 'endpoint',
            'ts': int(time.time()) - (len(df) - i) * 60,
            'host': 'cyberstash-win10',
            'process': process,
            'process_path': path,
            'pid': 1000 + i,
            'risk_tags': (['suspicious_path'] if is_sus_path else []) + (['suspicious_process'] if is_sus_proc else []),
        })

    payload = json.dumps({'source': 'cyberstash_csv1', 'rows': rows, 'meta': {'filename': filepath.name}}).encode()
    req = urllib.request.Request(
        f'{server}/api/v1/ingest/batch',
        data=payload,
        method='POST',
        headers={**HEADERS, 'Content-Type': 'application/json'},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read())
            return result.get('session_id') or result.get('batch_id')
    except urllib.error.HTTPError as e:
        body_text = e.read().decode(errors='replace')
        print(f"  [WARN] Ingest HTTP {e.code}: {body_text[:300]}")
        # Try alternate endpoint
        return None
    except Exception as e:
        print(f"  [WARN] Ingest failed: {e}")
        return None


def run(server: str) -> None:
    print(f"\n{'='*60}")
    print("  JanuSec CyberStash Report Generator")
    print(f"  Server: {server}")
    print(f"{'='*60}\n")

    # --- Health check ---
    import urllib.request
    req = urllib.request.Request(f'{server}/api/v1/health', headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            health = json.loads(r.read())
            print(f"[+] Server health: {health.get('status', 'unknown')}\n")
    except Exception as e:
        print(f"[!] Cannot reach server at {server}: {e}")
        print("    Start server first: python start_simple.py --port 8090 --no-reload")
        sys.exit(1)

    results = []

    for filepath in FILES:
        if not filepath.exists():
            print(f"[!] File not found: {filepath}")
            continue

        slug = filepath.stem.replace(' ', '_').lower()
        print(f"\n{'─'*60}")
        print(f"  Processing: {filepath.name}")
        print(f"{'─'*60}")

        # --- Upload file ---
        print(f"  [1/3] Uploading to pipeline...")
        session_id = None

        if filepath.name == 'cybstash csv1.xlsx':
            # CSV1 is a flat path list — upload directly as Excel via csv/upload
            # which handles the path column as process telemetry
            upload_result = upload_excel(server, filepath)
            session_id = (
                upload_result.get('session_id')
                or upload_result.get('batch_id')
                or upload_result.get('id')
            )
            if not session_id and 'sessions' in upload_result:
                sessions_list = upload_result.get('sessions') or []
                session_id = sessions_list[0] if sessions_list else None
            print(f"       Upload result keys: {list(upload_result.keys())}")
            if session_id:
                print(f"       Session ID: {session_id}")
        else:
            upload_result = upload_excel(server, filepath)
            session_id = (
                upload_result.get('session_id')
                or upload_result.get('batch_id')
                or upload_result.get('id')
            )
            if not session_id and 'sessions' in upload_result:
                sessions_list = upload_result['sessions']
                session_id = sessions_list[0] if sessions_list else None
            print(f"       Upload result keys: {list(upload_result.keys())}")
            if session_id:
                print(f"       Session ID: {session_id}")

        if not session_id:
            print(f"  [WARN] No session_id returned — using synthetic session for report demo")
            session_id = f'cyberstash-{slug}-demo'

        print(f"  [2/3] Waiting for pipeline processing (3s)...")
        time.sleep(3)

        # --- Generate reports for each persona ---
        print(f"  [3/3] Generating reports for all personas...\n")
        file_results = {'file': filepath.name, 'session_id': session_id, 'reports': {}}

        for persona in PERSONAS:
            print(f"       Persona: {persona:16s}", end=' ', flush=True)

            # JSON report
            report_json = generate_report(server, session_id, persona)
            # HTML report
            html = generate_html_report(server, session_id, persona)

            out_path_html = OUT_DIR / f'cyberstash_{slug}_{persona}.html'
            out_path_json = OUT_DIR / f'cyberstash_{slug}_{persona}.json'

            if html:
                out_path_html.write_text(html, encoding='utf-8')
                size_kb = len(html) // 1024
                print(f"HTML={size_kb}KB ", end='', flush=True)
            else:
                print(f"HTML=FAILED ", end='', flush=True)

            if report_json:
                out_path_json.write_text(json.dumps(report_json, indent=2, default=str), encoding='utf-8')
                verdict = (report_json.get('verdict_stats') or {})
                alerts = len(report_json.get('flagged_events') or report_json.get('alerts') or [])
                print(f"JSON=OK alerts={alerts}")
            else:
                print(f"JSON=FAILED")

            file_results['reports'][persona] = {
                'html': str(out_path_html) if html else None,
                'json': str(out_path_json) if report_json else None,
                'alert_count': alerts if report_json else 0,
            }

        results.append(file_results)

    # --- Summary ---
    print(f"\n{'='*60}")
    print("  REPORT SUMMARY")
    print(f"{'='*60}")
    all_ok = True
    for fr in results:
        print(f"\n  File: {fr['file']}  (session: {fr['session_id']})")
        for persona, rpt in fr['reports'].items():
            status = 'OK' if rpt.get('html') or rpt.get('json') else 'MISSING'
            if status == 'MISSING':
                all_ok = False
            print(f"    [{status}] {persona:20s} alerts={rpt.get('alert_count',0):3d}"
                  + (f"  -> {rpt['html']}" if rpt.get('html') else ''))

    print(f"\n{'='*60}")
    if all_ok:
        print("  All reports generated successfully!")
    else:
        print("  Some reports are missing — check warnings above.")
    print(f"  Output directory: {OUT_DIR}")
    print(f"{'='*60}\n")

    # Write manifest
    manifest_path = OUT_DIR / 'cyberstash_manifest.json'
    manifest_path.write_text(json.dumps(results, indent=2, default=str), encoding='utf-8')
    print(f"  Manifest: {manifest_path}\n")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate all-persona CyberStash reports')
    parser.add_argument('--server', default='http://localhost:8090', help='JanuSec server URL')
    args = parser.parse_args()
    run(args.server)
