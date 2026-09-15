"""Lightweight in-memory LLM cost and token tracker.

Provides two tracker classes and module-level singletons used across the app:
- ExternalLLMCostTracker: for external API calls (cost in $)
- LocalLLMTracker: for local/onnx/ollama calls (GPU time, no $)

This module is intentionally simple and safe for test environments.
"""
from __future__ import annotations
import threading
import time
import csv
import os
from typing import Dict, Any, Optional


class ExternalLLMCostTracker:
    def __init__(self):
        self._lock = threading.RLock()
        self.total_calls = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_cost = 0.0
        # per-model aggregates
        self.models: Dict[str, Dict[str, Any]] = {}
        # recent calls (kept short for memory)
        self.recent: list[Dict[str, Any]] = []
        self._max_recent = int(os.getenv('COST_TRACKER_MAX_RECENT', '200'))

    def track_call(self, row_index: int, model: str, input_tokens: int, output_tokens: int, cost: float):
        try:
            with self._lock:
                self.total_calls += 1
                self.total_input_tokens += int(input_tokens or 0)
                self.total_output_tokens += int(output_tokens or 0)
                self.total_cost += float(cost or 0.0)
                m = str(model or 'unknown')
                rec = self.models.get(m) or {'calls': 0, 'cost': 0.0, 'input_tokens': 0, 'output_tokens': 0}
                rec['calls'] += 1
                rec['cost'] += float(cost or 0.0)
                rec['input_tokens'] += int(input_tokens or 0)
                rec['output_tokens'] += int(output_tokens or 0)
                self.models[m] = rec
                entry = {
                    'ts': int(time.time()),
                    'row_index': int(row_index or -1),
                    'model': m,
                    'input_tokens': int(input_tokens or 0),
                    'output_tokens': int(output_tokens or 0),
                    'cost': float(cost or 0.0),
                }
                self.recent.append(entry)
                if len(self.recent) > self._max_recent:
                    self.recent = self.recent[-self._max_recent:]
        except Exception:
            # swallow errors to avoid breaking LLM flows
            pass

    def get_summary(self) -> Dict[str, Any]:
        with self._lock:
            return {
                'total_calls': int(self.total_calls),
                'total_input_tokens': int(self.total_input_tokens),
                'total_output_tokens': int(self.total_output_tokens),
                'total_cost': float(self.total_cost),
                'models': {k: dict(v) for k, v in self.models.items()},
                'recent': list(self.recent),
            }

    def export_csv(self, path: str) -> Optional[str]:
        try:
            with self._lock:
                with open(path, 'w', newline='', encoding='utf-8') as fh:
                    w = csv.DictWriter(fh, fieldnames=['ts','row_index','model','input_tokens','output_tokens','cost'])
                    w.writeheader()
                    for r in self.recent:
                        w.writerow(r)
            return path
        except Exception:
            return None


class LocalLLMTracker:
    def __init__(self):
        self._lock = threading.RLock()
        self.total_calls = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_gpu_time_ms = 0
        self.models: Dict[str, Dict[str, Any]] = {}
        self.recent: list[Dict[str, Any]] = []
        self._max_recent = int(os.getenv('COST_TRACKER_MAX_RECENT', '200'))

    def track_call(self, row_index: int, model: str, input_tokens: int, output_tokens: int, gpu_time_ms: int):
        try:
            with self._lock:
                self.total_calls += 1
                self.total_input_tokens += int(input_tokens or 0)
                self.total_output_tokens += int(output_tokens or 0)
                self.total_gpu_time_ms += int(gpu_time_ms or 0)
                m = str(model or 'local')
                rec = self.models.get(m) or {'calls': 0, 'gpu_time_ms': 0, 'input_tokens': 0, 'output_tokens': 0}
                rec['calls'] += 1
                rec['gpu_time_ms'] += int(gpu_time_ms or 0)
                rec['input_tokens'] += int(input_tokens or 0)
                rec['output_tokens'] += int(output_tokens or 0)
                self.models[m] = rec
                entry = {
                    'ts': int(time.time()),
                    'row_index': int(row_index or -1),
                    'model': m,
                    'input_tokens': int(input_tokens or 0),
                    'output_tokens': int(output_tokens or 0),
                    'gpu_time_ms': int(gpu_time_ms or 0),
                }
                self.recent.append(entry)
                if len(self.recent) > self._max_recent:
                    self.recent = self.recent[-self._max_recent:]
        except Exception:
            pass

    def get_summary(self) -> Dict[str, Any]:
        with self._lock:
            return {
                'total_calls': int(self.total_calls),
                'total_input_tokens': int(self.total_input_tokens),
                'total_output_tokens': int(self.total_output_tokens),
                'total_gpu_time_ms': int(self.total_gpu_time_ms),
                'models': {k: dict(v) for k, v in self.models.items()},
                'recent': list(self.recent),
            }


# Module-level singletons used by the application
EXTERNAL_TRACKER = ExternalLLMCostTracker()
LOCAL_TRACKER = LocalLLMTracker()

__all__ = [
    'ExternalLLMCostTracker', 'LocalLLMTracker', 'EXTERNAL_TRACKER', 'LOCAL_TRACKER'
]
 
