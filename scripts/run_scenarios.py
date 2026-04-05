#!/usr/bin/env python3
"""
Run endpoint and network-like scenarios against the local API and print a concise summary.

Usage:
  python scripts/run_scenarios.py --api http://localhost:8080
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from urllib import request, error


def post_json(url: str, payload: dict, timeout: float = 10.0) -> dict:
    data = json.dumps(payload).encode('utf-8')
    req = request.Request(url, data=data, method='POST')
    req.add_header('Content-Type', 'application/json')
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return json.loads(raw.decode('utf-8'))
    except error.HTTPError as e:
        msg = e.read().decode('utf-8', errors='ignore')
        raise RuntimeError(f"HTTP {e.code} posting to {url}: {msg}")


def get_text(url: str, timeout: float = 10.0) -> str:
    with request.urlopen(url, timeout=timeout) as resp:
        return resp.read().decode('utf-8', errors='ignore')


def endpoint_scenario(api: str) -> dict:
    """Simulate suspicious process lineage / LOLBin behavior."""
    payload = {
        "events": [
            {
                "id": "evt-ep-1",
                "host": "host-a",
                "process": {"name": "powershell.exe", "parent": "winword.exe", "cmd": "-nop -w hidden -enc AAAA"},
                "details": {"lolbin": True, "mitre": ["T1059", "T1204"]},
            }
        ],
        "classify": True,
        "include_rules": True,
        "send_alerts": True,
        "tenant_id": "tenantA",
    }
    res = post_json(f"{api}/api/v1/endpoints/log_batch", payload)
    evs = res.get("events") or []
    out = {
        "accepted": res.get("accepted"),
        "alerts_emitted": res.get("alerts_emitted"),
        "rules": evs[0].get("rules") if evs else [],
        "verdict": evs[0].get("verdict") if evs else None,
        "score": evs[0].get("score") if evs else None,
    }
    return out


def network_nxdomain_burst(api: str) -> dict:
    """Send a burst of NXDOMAIN-like DNS events for a host to trigger NX tracking and baselines."""
    events = []
    now = int(time.time() * 1000)
    # Warm-up phase: send some successful DNS before NX to establish a baseline
    for i in range(12):
        events.append({
            "id": f"evt-dns-ok-{now}-{i}",
            "host": "nx-host-1",
            "dns_rcode": 0,  # NOERROR
            "details": {"domain": f"ok-{i:02d}.example"},
        })
    for i in range(40):
        events.append({
            "id": f"evt-nx-{now}-{i}",
            "host": "nx-host-1",
            "dns_rcode": 3,  # NXDOMAIN
            "details": {"domain": f"dga-{i:02d}.example"},
        })
    payload = {
        "events": events,
        "classify": True,
        "include_rules": True,
        "send_alerts": False,
        "tenant_id": "tenantA",
    }
    res = post_json(f"{api}/api/v1/endpoints/log_batch", payload)
    evs = res.get("events") or []
    # Look for any baseline/cluster/enrich factors in the sample
    any_rules = []
    for e in evs:
        for r in e.get("rules", []) or []:
            if isinstance(r, str) and (
                r.startswith("baseline:") or r.startswith("cluster_") or r.startswith("enrich:") or r == 'zeek_high_nxdomain_rate'
            ):
                any_rules.append(r)
                break
    return {
        "accepted": res.get("accepted"),
        "sample_rules_detected": len(any_rules) > 0,
        "buffer_size": res.get("buffer_size"),
    }


def metrics_check(api: str) -> dict:
    txt = get_text(f"{api}/metrics")
    has_risk_hist = "risk_score_distribution" in txt
    has_sse = "detection_sse_decisions_total" in txt
    return {"risk_hist": has_risk_hist, "sse_decisions_counter": has_sse}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://localhost:8080")
    args = ap.parse_args()

    api = args.api.rstrip("/")
    # Health probe
    try:
        text = get_text(f"{api}/api/v1/health")
    except Exception as e:
        print(f"[health] FAIL: {e}")
        return 1
    else:
        print("[health] OK")

    # Endpoint scenario
    try:
        ep = endpoint_scenario(api)
        print(f"[endpoint] accepted={ep['accepted']} alerts={ep['alerts_emitted']} verdict={ep['verdict']} score={ep['score']} rules={ep['rules']}")
    except Exception as e:
        print(f"[endpoint] FAIL: {e}")
        return 1

    # Network NX burst
    try:
        nx = network_nxdomain_burst(api)
        print(f"[network] accepted={nx['accepted']} sample_rules_detected={nx['sample_rules_detected']} buffer_size={nx['buffer_size']}")
    except Exception as e:
        print(f"[network] FAIL: {e}")
        return 1

    # Metrics
    try:
        m = metrics_check(api)
        print(f"[metrics] risk_histogram={m['risk_hist']} sse_counter_present={m['sse_decisions_counter']}")
    except Exception as e:
        print(f"[metrics] FAIL: {e}")
        return 1

    print("[summary] scenarios completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
