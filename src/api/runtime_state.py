from __future__ import annotations

import asyncio
import os
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import FastAPI


def _default_custody_path() -> Path:
    return Path(os.getenv('FILE_BATCH_CUSTODY_PATH', 'data/file_batches/custody.jsonl'))


def _default_sanitized_events() -> deque[Dict[str, Any]]:
    return deque(maxlen=1000)


def _default_finops_log() -> Path:
    return Path(os.getenv('FINOPS_ANOMALY_LOG', 'artifacts/anomalies/finops_anomalies.log'))


def _default_nx_enabled() -> bool:
    return os.getenv('NX_RATE_TRACKER_ENABLED', '1').lower() not in {'0', 'false', 'no'}


def _default_nx_threshold() -> float:
    return float(os.getenv('ZEEK_NXDOMAIN_RATE_THRESHOLD', '0.35'))


def _default_nx_tracker() -> defaultdict[str, deque[bool]]:
    return defaultdict(lambda: deque(maxlen=50))


@dataclass
class ServerRuntime:
    file_hash_factors: Dict[str, List[str]] = field(default_factory=dict)
    file_batch_analysis: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    file_custody_path: Path = field(default_factory=_default_custody_path)
    sanitized_events: deque[Dict[str, Any]] = field(default_factory=_default_sanitized_events)
    dedup_cache: Dict[str, float] = field(default_factory=dict)
    finops_anomaly_log: Path = field(default_factory=_default_finops_log)
    nx_tracker_enabled: bool = field(default_factory=_default_nx_enabled)
    nx_rate_tracker: defaultdict[str, deque[bool]] = field(default_factory=_default_nx_tracker)
    nx_threshold_cache: float = field(default_factory=_default_nx_threshold)
    file_custody_lock: Optional[asyncio.Lock] = field(default=None, init=False)
    sanitized_lock: Optional[asyncio.Lock] = field(default=None, init=False)
    dedup_lock: Optional[asyncio.Lock] = field(default=None, init=False)

    def _ensure_lock(self, current: Optional[asyncio.Lock]) -> asyncio.Lock:
        if current is None:
            current = asyncio.Lock()
        return current

    def get_custody_lock(self) -> asyncio.Lock:
        self.file_custody_lock = self._ensure_lock(self.file_custody_lock)
        return self.file_custody_lock

    def get_sanitized_lock(self) -> asyncio.Lock:
        self.sanitized_lock = self._ensure_lock(self.sanitized_lock)
        return self.sanitized_lock

    def get_dedup_lock(self) -> asyncio.Lock:
        self.dedup_lock = self._ensure_lock(self.dedup_lock)
        return self.dedup_lock

    def reset_nx_tracker(self, threshold: float) -> None:
        self.nx_rate_tracker.clear()
        self.nx_threshold_cache = threshold

def get_server_runtime_state(app: 'FastAPI') -> ServerRuntime:
    runtime = getattr(app.state, '_server_runtime', None)
    if runtime is None:
        runtime = ServerRuntime()
        app.state._server_runtime = runtime
    return runtime

FILE_HASH_FACTORS: Dict[str, List[str]] | None = None
FILE_BATCH_ANALYSIS: Dict[str, Dict[str, Any]] | None = None

def get_file_hash_factors(runtime: ServerRuntime | None = None) -> Dict[str, List[str]]:
    global FILE_HASH_FACTORS
    if FILE_HASH_FACTORS is None:
        FILE_HASH_FACTORS = (runtime or ServerRuntime()).file_hash_factors
    return FILE_HASH_FACTORS

def get_file_batch_analysis(runtime: ServerRuntime | None = None) -> Dict[str, Dict[str, Any]]:
    global FILE_BATCH_ANALYSIS
    if FILE_BATCH_ANALYSIS is None:
        FILE_BATCH_ANALYSIS = (runtime or ServerRuntime()).file_batch_analysis
    return FILE_BATCH_ANALYSIS


__all__ = ['ServerRuntime', 'get_server_runtime_state', 'get_file_hash_factors', 'get_file_batch_analysis']
