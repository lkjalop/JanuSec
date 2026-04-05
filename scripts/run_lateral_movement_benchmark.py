#!/usr/bin/env python
"""
Run the lateral movement detector against recorded events and emit per-tenant logs.

Example:
    python scripts/run_lateral_movement_benchmark.py \
        --events tests/data/lateral_movement_sample.json \
        --tenant-id tenant-alpha
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List

from src.core.detectors.lateral_movement import detect_lateral_movement

LOG_DIR = Path("logs/perf/lateral_movement")
LOG_DIR.mkdir(parents=True, exist_ok=True)


def _load_runtime(path: Path) -> Any:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        conn_events = data.get("conn_events") or []
        auth_events = data.get("auth_events") or []
        azure_signins = data.get("azure_signins") or []
    elif isinstance(data, list):
        conn_events = data
        auth_events = []
        azure_signins = []
    else:
        conn_events = []
        auth_events = []
        azure_signins = []
    return SimpleNamespace(conn_events=conn_events, auth_events=auth_events, azure_signins=azure_signins)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the lateral movement detector and log results.")
    parser.add_argument("--events", type=Path, required=True, help="JSON file containing conn/auth/azure events.")
    parser.add_argument("--tenant-id", default="default", help="Tenant identifier for log labeling.")
    parser.add_argument("--output-dir", type=Path, default=LOG_DIR, help="Directory for result logs.")
    args = parser.parse_args()

    runtime = _load_runtime(args.events)
    factors = detect_lateral_movement(runtime)
    ts = int(time.time())
    output = {
        "tenant": args.tenant_id,
        "timestamp": ts,
        "events_file": str(args.events),
        "factor_count": len(factors),
        "factors": factors,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    out_path = args.output_dir / f"lateral_movement-{args.tenant_id}-{ts}.json"
    out_path.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"Wrote lateral movement benchmark for {args.tenant_id}: {out_path}")


if __name__ == "__main__":
    main()
