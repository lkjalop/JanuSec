#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import requests


def _load_records(path: Path) -> List[Dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    try:
        decoded = json.loads(text)
        if isinstance(decoded, list):
            return [item for item in decoded if isinstance(item, dict)]
        if isinstance(decoded, dict):
            for key in ("events", "value", "records", "items"):
                obj = decoded.get(key)
                if isinstance(obj, list):
                    return [item for item in obj if isinstance(item, dict)]
            return [decoded]
    except Exception:
        pass
    out: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except Exception:
            continue
        if isinstance(item, dict):
            out.append(item)
    return out


def _generate_records(mode: str, count: int) -> List[Dict[str, Any]]:
    """Generate synthetic events in-memory for soak testing without real input files."""
    now = int(time.time())
    records: List[Dict[str, Any]] = []

    if mode == "vpcflow":
        for i in range(count):
            records.append({
                "srcaddr": f"10.0.{i % 256}.{(i // 256) % 256}",
                "dstaddr": f"52.{i % 256}.{(i // 256) % 256}.1",
                "srcport": 1024 + (i % 60000),
                "dstport": [443, 80, 22, 3389, 8080][i % 5],
                "protocol": 6,
                "bytes": 512 + (i % 8192),
                "packets": 1 + (i % 100),
                "start": now - (i % 3600),
                "end": now - (i % 3600) + 30,
                "action": "ACCEPT" if i % 10 != 0 else "REJECT",
                "log-status": "OK",
                "account-id": f"123456789{i % 10:03d}",
                "vpc-id": f"vpc-{i % 20:08x}",
                "subnet-id": f"subnet-{i % 50:08x}",
                "interface-id": f"eni-{i:08x}",
            })

    elif mode == "eventhub":
        for i in range(count):
            ts = datetime.fromtimestamp(now - i, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            records.append({
                "id": hashlib.sha256(f"evt-{i}".encode()).hexdigest()[:16],
                "time": ts,
                "type": ["Microsoft.Security/assessments", "Microsoft.Authorization/policyAssignments/write",
                          "Microsoft.Network/networkSecurityGroups/write"][i % 3],
                "subject": f"/subscriptions/00000000-0000-0000-0000-{i:012d}/resourceGroups/rg-demo/providers/Microsoft.Compute/virtualMachines/vm-{i % 20}",
                "operationName": {
                    "value": ["Microsoft.Authorization/policyAssignments/write",
                               "Microsoft.Network/virtualNetworks/subnets/write",
                               "Microsoft.Compute/virtualMachines/start/action"][i % 3]
                },
                "properties": {
                    "status": ["Active", "Resolved", "Dismissed"][i % 3],
                    "severity": ["High", "Medium", "Low"][i % 3],
                },
                "callerIpAddress": f"203.{i % 256}.{(i // 256) % 256}.1",
                "claims": {"upn": f"user{i % 50}@contoso.com"},
            })

    elif mode == "sysmon":
        processes = ["powershell.exe", "cmd.exe", "explorer.exe", "notepad.exe", "mshta.exe", "wscript.exe"]
        parents = ["explorer.exe", "svchost.exe", "services.exe", "winlogon.exe"]
        for i in range(count):
            ts = datetime.fromtimestamp(now - i, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            proc = processes[i % len(processes)]
            records.append({
                "EventID": 1 + (i % 25),
                "Computer": f"WORKSTATION-{i % 50:03d}",
                "TimeCreated": ts,
                "ProcessName": proc,
                "CommandLine": f"{proc} /c echo {i}" if proc in ("cmd.exe",) else f"{proc} -NoP -W Hidden -Enc {hashlib.md5(str(i).encode()).hexdigest()[:24]}",
                "ParentProcessName": parents[i % len(parents)],
                "ProcessId": 1000 + (i % 60000),
                "ParentProcessId": 500 + (i % 1000),
                "User": f"CONTOSO\\user{i % 20:02d}",
                "Hash": f"SHA256={hashlib.sha256(f'proc-{i}'.encode()).hexdigest()}",
                "IntegrityLevel": ["High", "Medium", "Low", "System"][i % 4],
            })

    else:
        raise ValueError(f"unknown mode for --generate: {mode}")

    return records


def _headers(api_key: str, tenant_id: str) -> Dict[str, str]:
    return {
        "x-api-key": api_key,
        "x-tenant-id": tenant_id,
        "Content-Type": "application/json",
    }


def _chunks(items: List[Dict[str, Any]], batch_size: int) -> Iterable[List[Dict[str, Any]]]:
    for idx in range(0, len(items), batch_size):
        yield items[idx: idx + batch_size]


def _post_batch(base: str, mode: str, headers: Dict[str, str], batch: List[Dict[str, Any]]) -> Dict[str, Any]:
    if mode == "vpcflow":
        payload = {"events": batch, "classify": True, "send_alerts": False, "include_rules": False}
        resp = requests.post(f"{base}/api/v1/endpoints/log_batch", headers=headers, json=payload, timeout=60)
    elif mode == "eventhub":
        payload = {"value": batch}
        resp = requests.post(f"{base}/api/v1/iam/azure/webhook", headers=headers, json=payload, timeout=60)
    elif mode == "sysmon":
        payload = {"events": batch}
        resp = requests.post(f"{base}/api/v1/ingest/sysmon", headers=headers, json=payload, timeout=60)
    else:
        raise ValueError(f"unknown mode {mode}")
    resp.raise_for_status()
    return resp.json()


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Replay large cloud/endpoint corpora through Janusec ingest endpoints. "
                    "Use --generate N to produce synthetic events without an input file."
    )
    ap.add_argument("--base", default="http://127.0.0.1:8080")
    ap.add_argument("--api-key", default="devkey123")
    ap.add_argument("--tenant-id", required=True)
    ap.add_argument("--mode", choices=["vpcflow", "eventhub", "sysmon"], required=True)
    ap.add_argument("--input", default=None,
                    help="Path to JSON/JSONL input file. Omit when using --generate.")
    ap.add_argument("--generate", type=int, default=None, metavar="N",
                    help="Generate N synthetic events in-memory instead of loading from --input.")
    ap.add_argument("--batch-size", type=int, default=250)
    ap.add_argument("--iterations", type=int, default=1)
    ap.add_argument("--sleep", type=float, default=0.0)
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    if args.generate is None and args.input is None:
        ap.error("Provide --input <file> or --generate <N>.")

    base = args.base.rstrip("/")
    headers = _headers(args.api_key, args.tenant_id)

    if args.generate is not None:
        records = _generate_records(args.mode, args.generate)
        input_label = f"<synthetic:{args.generate}>"
    else:
        records = _load_records(Path(args.input))
        input_label = str(args.input)

    if not records:
        print("No records found in input.", file=sys.stderr)
        return 2

    report: Dict[str, Any] = {
        "tenant_id": args.tenant_id,
        "mode": args.mode,
        "input": input_label,
        "record_count": len(records),
        "batch_size": args.batch_size,
        "iterations": args.iterations,
        "batches": [],
    }
    sent = 0
    errors = 0
    started = time.time()
    for iteration in range(args.iterations):
        for batch_index, batch in enumerate(_chunks(records, args.batch_size)):
            batch_started = time.time()
            try:
                resp = _post_batch(base, args.mode, headers, batch)
                elapsed_ms = int((time.time() - batch_started) * 1000)
                sent += len(batch)
                report["batches"].append({
                    "iteration": iteration,
                    "batch_index": batch_index,
                    "size": len(batch),
                    "elapsed_ms": elapsed_ms,
                    "response": resp,
                    "ok": True,
                })
            except Exception as exc:
                elapsed_ms = int((time.time() - batch_started) * 1000)
                errors += 1
                report["batches"].append({
                    "iteration": iteration,
                    "batch_index": batch_index,
                    "size": len(batch),
                    "elapsed_ms": elapsed_ms,
                    "error": str(exc),
                    "ok": False,
                })
            if args.sleep > 0:
                time.sleep(args.sleep)

    duration = round(time.time() - started, 3)
    report["sent"] = sent
    report["errors"] = errors
    report["duration_s"] = duration
    report["events_per_second"] = round(sent / max(duration, 0.001), 2)
    report["ok"] = errors == 0

    text = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
    print(text)

    # Print human-readable summary
    status = "PASS" if errors == 0 else "FAIL"
    print(
        f"\n[{status}] mode={args.mode} sent={sent} errors={errors} "
        f"eps={report['events_per_second']} duration={duration}s",
        file=sys.stderr,
    )
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
