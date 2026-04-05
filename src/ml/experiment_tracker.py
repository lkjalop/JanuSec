"""Minimal Experiment Tracker (M3)

Writes experiment runs to a JSONL file for lightweight tracking without external deps.
Each record contains: ts, run_id, params, metrics, tags.
"""
from __future__ import annotations

import os
import json
import time
import uuid
from typing import Any, Dict, Optional


class ExperimentTracker:
    def __init__(self, out_path: Optional[str] = None) -> None:
        self.out_path = out_path or os.getenv('EXPERIMENT_LOG', 'experiments.jsonl')
        os.makedirs(os.path.dirname(self.out_path) or '.', exist_ok=True)

    def start_run(self, params: Dict[str, Any] | None = None, tags: Dict[str, Any] | None = None) -> str:
        run_id = str(uuid.uuid4())
        rec = {
            'ts': time.time(),
            'run_id': run_id,
            'event': 'start',
            'params': params or {},
            'tags': tags or {},
        }
        self._append(rec)
        return run_id

    def log_metrics(self, run_id: str, metrics: Dict[str, Any]) -> None:
        rec = {
            'ts': time.time(),
            'run_id': run_id,
            'event': 'metrics',
            'metrics': metrics,
        }
        self._append(rec)

    def end_run(self, run_id: str, status: str = 'completed') -> None:
        rec = {
            'ts': time.time(),
            'run_id': run_id,
            'event': 'end',
            'status': status,
        }
        self._append(rec)

    def _append(self, rec: Dict[str, Any]) -> None:
        with open(self.out_path, 'a', encoding='utf-8') as fh:
            fh.write(json.dumps(rec) + "\n")

    def summarize(self) -> Dict[str, Any]:
        """Parse JSONL and return a summary: run counts, last metrics per run, statuses, and a best-by metric."""
        import os
        if not os.path.exists(self.out_path):
            return {"runs": 0, "by_status": {}, "last_metrics": {}}
        by_status: Dict[str, int] = {}
        last_metrics: Dict[str, Dict[str, Any]] = {}
        runs = set()
        with open(self.out_path, 'r', encoding='utf-8') as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                rid = rec.get('run_id')
                if not rid:
                    continue
                runs.add(rid)
                evt = rec.get('event')
                if evt == 'metrics' and isinstance(rec.get('metrics'), dict):
                    last_metrics[rid] = rec['metrics']
                if evt == 'end':
                    st = str(rec.get('status', 'completed'))
                    by_status[st] = by_status.get(st, 0) + 1
        # Compute best by loglik if present
        best_run = None
        best_val = None
        for rid, m in last_metrics.items():
            v = m.get('loglik')
            if isinstance(v, (int, float)):
                if best_val is None or v > best_val:
                    best_val = v
                    best_run = rid
        return {"runs": len(runs), "by_status": by_status, "last_metrics": last_metrics, "best_by_loglik": {"run_id": best_run, "loglik": best_val}}


__all__ = ['ExperimentTracker']
