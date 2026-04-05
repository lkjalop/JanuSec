"""Minimal Experiment Tracker (M3)

Provides a lightweight, file-based tracker for experiments: logs config, metrics,
artifacts, and status to a directory structure under EXPERIMENTS_DIR (default ./experiments).

API:
  - start_experiment(name: str, config: dict) -> dict
  - log_metrics(run: dict, metrics: dict) -> None
  - log_artifact(run: dict, path: str, name: str | None = None) -> str
  - end_experiment(run: dict, status: str = "completed") -> None
"""
from __future__ import annotations

import json
import os
import shutil
import time
from typing import Dict, Any

EXPERIMENTS_DIR = os.getenv("EXPERIMENTS_DIR", "experiments")


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def start_experiment(name: str, config: Dict[str, Any]) -> Dict[str, Any]:
    ts = time.strftime("%Y%m%d-%H%M%S")
    run_id = f"{name}-{ts}"
    run_dir = os.path.join(EXPERIMENTS_DIR, run_id)
    _ensure_dir(run_dir)
    with open(os.path.join(run_dir, "config.json"), "w", encoding="utf-8") as fh:
        json.dump(config, fh, indent=2)
    run = {"id": run_id, "dir": run_dir, "status": "running", "start_ts": time.time()}
    with open(os.path.join(run_dir, "status.json"), "w", encoding="utf-8") as sh:
        json.dump(run, sh)
    return run


def log_metrics(run: Dict[str, Any], metrics: Dict[str, Any]) -> None:
    run_dir = run["dir"]
    _ensure_dir(run_dir)
    path = os.path.join(run_dir, "metrics.jsonl")
    with open(path, "a", encoding="utf-8") as mh:
        rec = {"ts": time.time(), **metrics}
        mh.write(json.dumps(rec) + "\n")


def log_artifact(run: Dict[str, Any], path: str, name: str | None = None) -> str:
    run_dir = run["dir"]
    _ensure_dir(run_dir)
    dest_dir = os.path.join(run_dir, "artifacts")
    _ensure_dir(dest_dir)
    base = name or os.path.basename(path)
    dest = os.path.join(dest_dir, base)
    shutil.copy2(path, dest)
    return dest


def end_experiment(run: Dict[str, Any], status: str = "completed") -> None:
    run_dir = run["dir"]
    with open(os.path.join(run_dir, "status.json"), "w", encoding="utf-8") as sh:
        run["status"] = status
        run["end_ts"] = time.time()
        json.dump(run, sh)

__all__ = [
    "start_experiment",
    "log_metrics",
    "log_artifact",
    "end_experiment",
]
