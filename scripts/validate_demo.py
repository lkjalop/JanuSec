#!/usr/bin/env python3
"""
Demo Readiness Validator

Runs a barrage of Zeek-like and endpoint events against the running API,
checks health, SSE stream, metrics, and basic frontend availability.

Usage:
  python scripts/validate_demo.py --api http://localhost:8080 --scenarios 4 --events 12 --timeout 30
"""
from __future__ import annotations
import argparse
import json
import sys
import time
import random
from typing import Any, Dict, List

import requests


def gen_benign_conn(hosts: List[str]) -> Dict[str, Any]:
    return {
        "id": f"conn-benign-{int(time.time()*1000)}",
        "ts": time.time(),
        "host": random.choice(hosts),
        "user": "zeek",
        "proc_name": "zeek:http",
        "dest_ip": "8.8.8.8",
        "dest_port": 80,
        "proto": "tcp",
        "duration": random.uniform(0.1, 2.0),
        "orig_bytes": random.randint(100, 1000),
        "resp_bytes": random.randint(500, 5000),
        "tags": ["zeek", "conn", "benign"],
    }


def gen_suspicious_dns(hosts: List[str], c2_domains: List[str]) -> Dict[str, Any]:
    name = random.choice(c2_domains + [f"random-dga-{random.randint(1000,9999)}.com"])
    return {
        "id": f"dns-suspicious-{int(time.time()*1000)}",
        "ts": time.time(),
        "host": random.choice(hosts),
        "user": "zeek",
        "proc_name": "zeek:dns",
        "dest_ip": "8.8.8.8",
        "dest_port": 53,
        "dns_rcode": "NXDOMAIN" if random.random() > 0.3 else "NOERROR",
        "dns_query": name,
        "tags": ["zeek", "dns", "suspicious"],
    }


def gen_beacon(hosts: List[str], sips: List[str]) -> Dict[str, Any]:
    return {
        "id": f"beacon-malicious-{int(time.time()*1000)}",
        "ts": time.time(),
        "host": random.choice(hosts),
        "user": "zeek",
        "proc_name": "zeek:conn",
        "dest_ip": random.choice(sips),
        "dest_port": 4444,
        "proto": "tcp",
        "duration": 300,
        "orig_bytes": 128,
        "resp_bytes": 64,
        "service": "unknown",
        "tags": ["zeek", "conn", "c2-beacon", "malicious"],
    }


def gen_macro_attack(hosts: List[str], sips: List[str]) -> Dict[str, Any]:
    return {
        "id": f"macro-attack-{int(time.time()*1000)}",
        "ts": time.time(),
        "host": random.choice(hosts),
        "event_type": "process_start",
        "proc_name": "powershell.exe",
        "parent_proc": "winword.exe",
        "command_line": "powershell.exe -enc JABhAD0AJwBoAHQAdABwADoALwAvAGMAMgAuAGUAdgBpAGwALgBjAG8AbQAnAA==",
        "dest_ip": random.choice(sips),
        "tags": ["endpoint", "macro", "powershell", "malicious"],
    }


def post_batch(api: str, events: List[Dict[str, Any]]) -> bool:
    try:
        r = requests.post(f"{api}/api/v1/endpoints/log_batch", json={"events": events, "classify": True}, timeout=15)
        return r.status_code == 200
    except Exception:
        return False


def check_health(api: str, timeout: int = 30) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(f"{api}/docs", timeout=3)
            if r.status_code in (200, 404):
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def check_metrics(api: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"ok": False}
    try:
        r = requests.get(f"{api}/metrics", timeout=10)
        if r.status_code != 200:
            return out
        text = r.text
        # Simple extractions
        out["ok"] = True
        out["decisions_total"] = sum(1 for line in text.splitlines() if 'decisions_total' in line and not line.startswith('#'))
        out["risk_score_lines"] = sum(1 for line in text.splitlines() if 'risk_score_distribution' in line and not line.startswith('#'))
    except Exception:
        pass
    return out


def check_sse(api: str, timeout: int = 5) -> bool:
    try:
        with requests.get(f"{api}/api/v1/stream/decisions", stream=True, timeout=timeout) as r:
            it = r.iter_content(chunk_size=128)
            start = time.time()
            for chunk in it:
                if chunk:
                    # Accept sentinel or keepalive
                    if b'data:' in chunk or b':keepalive' in chunk:
                        return True
                if time.time() - start > timeout:
                    break
    except Exception:
        return False
    return False


def check_frontend(api: str) -> bool:
    # Try react and ui mounts
    for path in ("/react", "/ui", "/"):
        try:
            r = requests.get(f"{api}{path}", timeout=5)
            if r.status_code == 200:
                return True
        except Exception:
            continue
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://localhost:8080")
    ap.add_argument("--scenarios", type=int, default=4)
    ap.add_argument("--events", type=int, default=12)
    ap.add_argument("--timeout", type=int, default=30)
    args = ap.parse_args()

    api = args.api.rstrip('/')

    print("[health] Waiting for API...")
    if not check_health(api, timeout=args.timeout):
        print("[health] API not responding in time", file=sys.stderr)
        return 2

    hosts = ["DESKTOP-ABC123", "LAPTOP-XYZ789", "SERVER-DEF456"]
    sips = ["192.168.1.100", "10.0.0.15", "172.16.1.50"]
    c2_domains = ["evil-c2.com", "malware-beacon.net", "data-exfil.org"]

    print("[ingest] Sending events...")
    sent = 0
    per = max(1, args.events // max(1, args.scenarios))
    for i in range(args.scenarios):
        batch: List[Dict[str, Any]] = []
        if i % 4 == 0:
            batch = [gen_benign_conn(hosts) for _ in range(per)]
        elif i % 4 == 1:
            batch = [gen_suspicious_dns(hosts, c2_domains) for _ in range(per)]
        elif i % 4 == 2:
            batch = [gen_beacon(hosts, sips) for _ in range(max(1, per // 2))]
        else:
            batch = [gen_macro_attack(hosts, sips) for _ in range(max(1, per // 2))]
        if post_batch(api, batch):
            sent += len(batch)
        time.sleep(0.5)
    print(f"[ingest] Sent {sent} events")

    print("[metrics] Checking metrics...")
    m = check_metrics(api)
    if not m.get("ok"):
        print("[metrics] scrape failed", file=sys.stderr)
        return 3
    print(f"  decisions_total lines: {m.get('decisions_total')}  risk_score lines: {m.get('risk_score_lines')}")

    print("[sse] Checking decisions stream...")
    if not check_sse(api, timeout=5):
        print("[sse] stream did not yield quickly", file=sys.stderr)
        return 4

    print("[frontend] Checking frontend mounts...")
    if not check_frontend(api):
        print("[frontend] frontend not available", file=sys.stderr)
        # Not fatal for API demo; continue

    print("[summary] Demo readiness checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
