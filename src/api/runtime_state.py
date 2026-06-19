from __future__ import annotations

import asyncio
import os
import time
from collections import defaultdict, deque, OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional
from src.domains.iam.graph_store import PermissionGraphStore
import json
import sys

# Ensure compatibility alias so `api.runtime_state` resolves to this module.
sys.modules.setdefault('api.runtime_state', sys.modules[__name__])


# Lightweight attribute-access wrapper for dicts so tests can use `rec.factors`.
class _AttrDict(dict):
    def __getattr__(self, name: str):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name: str, value: Any):
        if name.startswith('_'):
            return super().__setattr__(name, value)
        self[name] = value

    def __delattr__(self, name: str):
        try:
            del self[name]
        except KeyError:
            raise AttributeError(name)


if TYPE_CHECKING:
    from fastapi import FastAPI


def _default_custody_path() -> Path:
    return Path(os.getenv('FILE_BATCH_CUSTODY_PATH', 'data/file_batches/custody.jsonl'))


def _default_sanitized_events() -> deque[dict[str, Any]]:
    return deque(maxlen=1000)


def _default_finops_log() -> Path:
    return Path(os.getenv('FINOPS_ANOMALY_LOG', 'artifacts/anomalies/finops_anomalies.log'))


def _default_nx_enabled() -> bool:
    return os.getenv('NX_RATE_TRACKER_ENABLED', '1').lower() not in {'0', 'false', 'no'}


def _default_nx_threshold() -> float:
    return float(os.getenv('ZEEK_NXDOMAIN_RATE_THRESHOLD', '0.35'))


def _default_nx_tracker() -> defaultdict[str, deque[bool]]:
    return defaultdict(lambda: deque(maxlen=50))


def _default_file_hash_history_maxlen() -> int:
    try:
        return int(os.getenv('FILE_HASH_HISTORY_MAXLEN', '200') or 200)
    except Exception:
        return 200


def _default_file_hash_factors() -> defaultdict[str, deque[float]]:
    maxlen = _default_file_hash_history_maxlen()
    return defaultdict(lambda: deque(maxlen=maxlen))


def _event_buffer_size(env_key: str, default: int) -> int:
    try:
        value = int(os.getenv(env_key, str(default)) or default)
        return max(32, value)
    except Exception:
        return default


def _default_file_event_buffer() -> deque[dict[str, Any]]:
    return deque(maxlen=_event_buffer_size('RUNTIME_FILE_EVENT_MAXLEN', 800))


def _default_process_event_buffer() -> deque[dict[str, Any]]:
    return deque(maxlen=_event_buffer_size('RUNTIME_PROCESS_EVENT_MAXLEN', 800))


def _default_registry_event_buffer() -> deque[dict[str, Any]]:
    return deque(maxlen=_event_buffer_size('RUNTIME_REGISTRY_EVENT_MAXLEN', 400))


def _default_service_event_buffer() -> deque[dict[str, Any]]:
    return deque(maxlen=_event_buffer_size('RUNTIME_SERVICE_EVENT_MAXLEN', 400))


def _default_network_event_buffer() -> deque[dict[str, Any]]:
    return deque(maxlen=_event_buffer_size('RUNTIME_NETWORK_EVENT_MAXLEN', 800))


@dataclass
class ServerRuntime:
    # Maintain file hash occurrence counts (int) for rarity calculations.
    # Previously this stored lists of factors; we now store integer counts for
    # memory hygiene. Factor details remain available in custody records if needed.
    # file_hash_factors: mapping sha -> deque[timestamp]; bounded by FILE_HASH_HISTORY_MAXLEN
    file_hash_factors: defaultdict[str, deque[float]] = field(default_factory=_default_file_hash_factors)
    file_batch_analysis: dict[str, dict[str, Any]] = field(default_factory=dict)
    file_custody_path: Path = field(default_factory=_default_custody_path)
    sanitized_events: deque[dict[str, Any]] = field(default_factory=_default_sanitized_events)
    dedup_cache: dict[str, float] = field(default_factory=dict)
    finops_anomaly_log: Path = field(default_factory=_default_finops_log)
    nx_tracker_enabled: bool = field(default_factory=_default_nx_enabled)
    nx_rate_tracker: defaultdict[str, deque[bool]] = field(default_factory=_default_nx_tracker)
    nx_threshold_cache: float = field(default_factory=_default_nx_threshold)
    # EWMA history store: maps a correlation key (e.g. "batchA|batchB") -> float
    # EWMA history: key -> (value, last_updated_ts)
    ewma_history: dict[str, tuple[float, float]] = field(default_factory=dict)
    # Persisted EWMA history file path (optional)
    ewma_persist_path: Optional[Path] = field(default_factory=lambda: Path(os.getenv('EWMA_HISTORY_PATH', 'data/sessions/ewma_history.json')))
    # Beacon periodicity scores keyed by node id -> (score, details, last_ts)
    beacon_scores: dict[str, tuple[float, dict, float]] = field(default_factory=dict)
    # False-positive labels storage: key -> label record
    fp_labels: dict[str, dict] = field(default_factory=dict)
    # Factor occurrence counters (for FP ratio metrics)
    fp_factor_counts: dict[str, int] = field(default_factory=dict)
    fp_factor_fp_labels_counts: dict[str, int] = field(default_factory=dict)
    file_custody_lock: asyncio.Lock | None = field(default=None, init=False)
    sanitized_lock: asyncio.Lock | None = field(default=None, init=False)
    dedup_lock: asyncio.Lock | None = field(default=None, init=False)
    # Tenant partitions: tenant_id -> lightweight maps for isolation
    tenants: dict[str, dict] = field(default_factory=dict)
    # Pending replay jobs queue (list of dict) for health/monitoring
    replay_jobs: list[dict] = field(default_factory=list)
    # Cached factor embeddings (adaptive scheduler populates)
    factor_embeddings: dict[str, list[float]] = field(default_factory=dict)
    # LLM training feedback metrics shared with UI
    llm_feedback_metrics: Dict[str, Any] = field(default_factory=dict)
    file_events: deque[dict[str, Any]] = field(default_factory=_default_file_event_buffer)
    process_events: deque[dict[str, Any]] = field(default_factory=_default_process_event_buffer)
    registry_events: deque[dict[str, Any]] = field(default_factory=_default_registry_event_buffer)
    service_events: deque[dict[str, Any]] = field(default_factory=_default_service_event_buffer)
    network_events: deque[dict[str, Any]] = field(default_factory=_default_network_event_buffer)

    def _ensure_lock(self, current: asyncio.Lock | None) -> asyncio.Lock:
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

    def _append_event(self, attr: str, event: Dict[str, Any], tenant_id: str | None = None) -> None:
        if not isinstance(event, dict):
            return
        try:
            bucket = getattr(self, attr, None)
        except Exception:
            bucket = None
        if not isinstance(bucket, deque):
            return
        item = dict(event)
        if tenant_id:
            item.setdefault('tenant_id', tenant_id)
        ts = item.get('timestamp') or item.get('ts') or time.time()
        try:
            item['timestamp'] = float(ts)
        except Exception:
            item['timestamp'] = time.time()
        bucket.append(item)

    def record_endpoint_event(self, attr: str, event: Dict[str, Any], tenant_id: str | None = None) -> None:
        self._append_event(attr, event, tenant_id)

    def record_file_event(self, event: Dict[str, Any], tenant_id: str | None = None) -> None:
        self.record_endpoint_event('file_events', event, tenant_id)

    def record_process_event(self, event: Dict[str, Any], tenant_id: str | None = None) -> None:
        self.record_endpoint_event('process_events', event, tenant_id)

    def record_registry_event(self, event: Dict[str, Any], tenant_id: str | None = None) -> None:
        self.record_endpoint_event('registry_events', event, tenant_id)

    def record_service_event(self, event: Dict[str, Any], tenant_id: str | None = None) -> None:
        self.record_endpoint_event('service_events', event, tenant_id)

    def record_network_event(self, event: Dict[str, Any], tenant_id: str | None = None) -> None:
        self.record_endpoint_event('network_events', event, tenant_id)

    def snapshot_endpoint_events(self, tenant_id: str | None = None) -> Dict[str, List[Dict[str, Any]]]:
        view: Dict[str, List[Dict[str, Any]]] = {}
        keys = ['file_events', 'process_events', 'registry_events', 'service_events', 'network_events']
        for key in keys:
            data = getattr(self, key, None)
            if isinstance(data, deque):
                vals = list(data)
            elif isinstance(data, list):
                vals = list(data)
            else:
                vals = []
            if tenant_id:
                try:
                    vals = [item for item in vals if item.get('tenant_id') == tenant_id]
                except Exception:
                    pass
            view[key] = vals
        return view


def _record_helper(runtime: ServerRuntime | None, attr: str, event: Dict[str, Any], tenant_id: str | None = None) -> None:
    if runtime is None:
        return
    try:
        runtime.record_endpoint_event(attr, event, tenant_id)
    except Exception:
        pass


def record_file_event(runtime: ServerRuntime | None, event: Dict[str, Any], tenant_id: str | None = None) -> None:
    _record_helper(runtime, 'file_events', event, tenant_id)


def record_process_event(runtime: ServerRuntime | None, event: Dict[str, Any], tenant_id: str | None = None) -> None:
    _record_helper(runtime, 'process_events', event, tenant_id)


def record_registry_event(runtime: ServerRuntime | None, event: Dict[str, Any], tenant_id: str | None = None) -> None:
    _record_helper(runtime, 'registry_events', event, tenant_id)


def record_service_event(runtime: ServerRuntime | None, event: Dict[str, Any], tenant_id: str | None = None) -> None:
    _record_helper(runtime, 'service_events', event, tenant_id)


def record_network_event(runtime: ServerRuntime | None, event: Dict[str, Any], tenant_id: str | None = None) -> None:
    _record_helper(runtime, 'network_events', event, tenant_id)


def ingest_endpoint_events(runtime: ServerRuntime | None, events: Iterable[Dict[str, Any]] | None, tenant_id: str | None = None) -> None:
    if runtime is None or not events:
        return
    for event in events:
        if not isinstance(event, dict):
            continue
        payload = dict(event)
        if tenant_id:
            payload.setdefault('tenant_id', tenant_id)
        recorded = False
        if payload.get('path') or payload.get('file_hash') or payload.get('entropy') is not None:
            record_file_event(runtime, payload, tenant_id)
            recorded = True
        if payload.get('process') or payload.get('exe') or payload.get('command_line'):
            record_process_event(runtime, payload, tenant_id)
            recorded = True
        key = (payload.get('key') or payload.get('registry_key') or '').lower()
        if key:
            record_registry_event(runtime, payload, tenant_id)
            recorded = True
        service = payload.get('service') or payload.get('service_name')
        if service:
            record_service_event(runtime, payload, tenant_id)
            recorded = True
        if payload.get('ip') or payload.get('ip_dst') or payload.get('domain') or payload.get('outbound'):
            record_network_event(runtime, payload, tenant_id)
            recorded = True
        if not recorded:
            # Default to process bucket for generic endpoint events
            record_process_event(runtime, payload, tenant_id)


def get_server_runtime_state(app: FastAPI) -> ServerRuntime:
    runtime = getattr(app.state, '_server_runtime', None)
    if runtime is None:
        runtime = ServerRuntime()
        app.state._server_runtime = runtime
    return runtime


def update_connector_health(
    runtime: "ServerRuntime | None",
    tenant_id: str,
    connector_name: str,
    *,
    provider: str = "",
    status: str = "ok",
    ok: bool = True,
    last_count: int = 0,
    error: str | None = None,
    checkpoint: "dict | None" = None,
    **metadata: Any,
) -> None:
    """Update connector health state in the runtime store."""
    try:
        if runtime is None:
            return
        tenant = runtime.tenants.setdefault(tenant_id, {})
        if not isinstance(tenant.get('connector_health'), dict):
            tenant['connector_health'] = {}
        existing = tenant['connector_health'].setdefault(connector_name, {})
        import time as _time
        now = _time.time()
        existing.update({
            'provider': provider or existing.get('provider', ''),
            'status': status,
            'ok': ok,
            'last_count': last_count,
            'last_poll_ts': now,
        })
        existing.setdefault('authenticated', bool(ok))
        existing.setdefault('receiving_events', bool(last_count))
        existing.setdefault('checkpoint_healthy', checkpoint is not None)
        existing.setdefault('beta_ready', bool(ok))
        freshness = existing.setdefault('freshness', {})
        if isinstance(freshness, dict):
            freshness.setdefault('last_poll_ts', now)
            freshness.setdefault('heartbeat_stale', False)
        if ok:
            existing['last_ok_ts'] = now
            existing['consecutive_failures'] = 0
        else:
            existing['last_error'] = error
            existing['consecutive_failures'] = existing.get('consecutive_failures', 0) + 1
        if checkpoint is not None:
            existing['checkpoint'] = checkpoint
        for key, value in metadata.items():
            if value is not None:
                existing[key] = value
    except Exception:
        pass


def get_connector_health(
    runtime: "ServerRuntime | None",
    tenant_id: str,
    connector_name: "str | None" = None,
) -> dict:
    """Return connector health dict for tenant. If connector_name given, return single entry."""
    try:
        if runtime is None:
            return {}
        tenant = runtime.tenants.get(tenant_id, {})
        health = tenant.get('connector_health', {})
        if connector_name is not None:
            return health.get(connector_name, {})
        return health
    except Exception:
        return {}


FILE_HASH_FACTORS: dict[str, int] | None = None
FILE_BATCH_ANALYSIS: dict[str, dict[str, Any]] | None = None


def get_file_hash_factors(runtime: ServerRuntime | None = None) -> defaultdict[str, deque[float]]:
    global FILE_HASH_FACTORS
    if FILE_HASH_FACTORS is None:
        FILE_HASH_FACTORS = (runtime or ServerRuntime()).file_hash_factors
    return FILE_HASH_FACTORS


def get_tenant_runtime(runtime: ServerRuntime | None = None, tenant_id: str | None = None) -> dict:
    """Return a tenant-scoped mapping of runtime-like pieces.

    If tenant_id is None or 'global', return top-level runtime mappings for
    backward compatibility. Otherwise lazily create a tenant partition with
    isolated structures.
    """
    if runtime is None:
        runtime = _RUNTIME
    if not tenant_id or str(tenant_id).lower() in {'global','none',''}:
        return {
            'file_hash_factors': runtime.file_hash_factors,
            'nx_rate_tracker': runtime.nx_rate_tracker,
            'ewma_history': runtime.ewma_history,
            'beacon_scores': runtime.beacon_scores,
            'fp_labels': runtime.fp_labels,
            'last_access': time.time()
        }
    # New function to get permission graph
def get_permission_graph(runtime: ServerRuntime | None = None, tenant_id: str | None = None) -> PermissionGraphStore:
    """Return a PermissionGraphStore instance persisted per-tenant (or global).

    This function lazily creates a PermissionGraphStore and attaches it to the
    tenant partition so callers can upsert/query graphs without needing to
    manage persistence paths.
    """
    if runtime is None:
        runtime = _RUNTIME
    # Choose tenant vs global path
    tid = None if not tenant_id or str(tenant_id).lower() in {'global','none',''} else str(tenant_id)
    key = f'permission_graph::{tid or "global"}'
    # store in top-level runtime.tenants_map to persist the object
    if tid is None:
        # global attachment
        if not hasattr(runtime, '_permission_graph_global') or getattr(runtime, '_permission_graph_global') is None:
            # persist path optional
            persist_dir = Path(os.getenv('TENANT_PERSIST_DIR','data/tenants'))
            persist_dir.mkdir(parents=True, exist_ok=True)
            path = persist_dir / 'global_permission_graph.json'
            runtime._permission_graph_global = PermissionGraphStore(str(path))
        return runtime._permission_graph_global
    # tenant partition
    tmap = runtime.tenants.get(tid)
    if tmap is None:
        tmap = get_tenant_runtime(runtime, tid)
    if tmap is None:
        tmap = {
            'file_hash_factors': defaultdict(lambda: deque(maxlen=_default_file_hash_history_maxlen())),
            'nx_rate_tracker': defaultdict(lambda: deque(maxlen=50)),
            'ewma_history': {},
            'beacon_scores': {},
            'fp_labels': {},
            'last_access': time.time(),
        }
        runtime.tenants[tid] = tmap
    if 'permission_graph' not in tmap or tmap.get('permission_graph') is None:
        base = Path(os.getenv('TENANT_PERSIST_DIR','data/tenants')) / tid
        base.mkdir(parents=True, exist_ok=True)
        p = base / 'permission_graph.json'
        tmap['permission_graph'] = PermissionGraphStore(str(p))
    return tmap['permission_graph']
    tid = str(tenant_id)
    tmap = runtime.tenants.get(tid)
    if tmap is None:
        tmap = {
            'file_hash_factors': defaultdict(lambda: deque(maxlen=_default_file_hash_history_maxlen())),
            'nx_rate_tracker': defaultdict(lambda: deque(maxlen=50)),
            'ewma_history': {},
            'beacon_scores': {},
            'fp_labels': {},
            'last_access': time.time()
        }
        runtime.tenants[tid] = tmap
        # Attempt best-effort load from disk for this tenant partition
        try:
            _tenant_dir = Path(os.getenv('TENANT_PERSIST_DIR','data/tenants')) / tid
            _tenant_file = _tenant_dir / 'runtime.json'
            if _tenant_file.exists():
                with open(_tenant_file, 'r', encoding='utf8') as fh:
                    data = json.load(fh)
                # merge known submaps
                try:
                    if isinstance(data.get('ewma_history'), dict):
                        tmap['ewma_history'].update(data.get('ewma_history'))
                except Exception:
                    pass
                try:
                    if isinstance(data.get('fp_labels'), dict):
                        tmap['fp_labels'].update(data.get('fp_labels'))
                except Exception:
                    pass
                try:
                    if isinstance(data.get('beacon_scores'), dict):
                        tmap['beacon_scores'].update(data.get('beacon_scores'))
                except Exception:
                    pass
        except Exception:
            pass
    else:
        try:
            tmap['last_access'] = time.time()
        except Exception:
            pass
    return tmap


def persist_tenant_runtime(runtime: ServerRuntime | None = None, tenant_id: str | None = None) -> None:
    """Persist a tenant partition to data/tenants/{tenant}/runtime.json (best-effort)."""
    if runtime is None or not tenant_id:
        return
    try:
        tid = str(tenant_id)
        tmap = runtime.tenants.get(tid)
        if not tmap:
            return
        base = Path(os.getenv('TENANT_PERSIST_DIR','data/tenants')) / tid
        base.mkdir(parents=True, exist_ok=True)
        out = base / 'runtime.json'
        # Only persist a subset of fields
        to_save = {
            'ewma_history': tmap.get('ewma_history', {}),
            'fp_labels': tmap.get('fp_labels', {}),
            'beacon_scores': tmap.get('beacon_scores', {}),
            'last_access': tmap.get('last_access', time.time())
        }
        tmp = out.with_suffix('.tmp')
        with open(tmp, 'w', encoding='utf8') as fh:
            json.dump(to_save, fh)
        tmp.replace(out)
    except Exception:
        pass


def get_file_batch_analysis(runtime: ServerRuntime | None = None) -> dict[str, dict[str, Any]]:
    global FILE_BATCH_ANALYSIS
    # Prefer the canonical runtime instance's mapping when available so callers
    # always see the same shared state (tests and runtime may reference either
    # the module-level alias or the server runtime). Keep the module-level
    # alias synchronized to avoid visibility issues across import order.
    if runtime is None:
        # If module-level alias already exists and has been populated by a prior
        # call (tests often seed it by calling get_file_batch_analysis(runtime)),
        # return it to avoid clobbering with the default _RUNTIME mapping.
        if FILE_BATCH_ANALYSIS is not None:
            return FILE_BATCH_ANALYSIS
        try:
            runtime = _RUNTIME
        except Exception:
            runtime = None
    if runtime is not None:
        try:
            # ensure module alias references the same dict
            FILE_BATCH_ANALYSIS = runtime.file_batch_analysis
            return FILE_BATCH_ANALYSIS
        except Exception:
            pass
    if FILE_BATCH_ANALYSIS is None:
        FILE_BATCH_ANALYSIS = (runtime or ServerRuntime()).file_batch_analysis
    return FILE_BATCH_ANALYSIS


def cleanup_file_hash_history(runtime: ServerRuntime | None = None, ttl_seconds: int = 60 * 60 * 24 * 7) -> None:
    """Prune timestamps older than ttl_seconds from runtime.file_hash_factors."""
    if runtime is None:
        runtime = _RUNTIME
    try:
        now = time.time()
        for sha, dq in list(getattr(runtime, 'file_hash_factors', {}).items()):
            try:
                # pop left until newest within ttl
                while dq and (now - dq[0]) > ttl_seconds:
                    dq.popleft()
                if not dq:
                    # remove empty entries to save memory
                    try:
                        runtime.file_hash_factors.pop(sha, None)
                    except Exception:
                        pass
            except Exception:
                continue
    except Exception:
        pass


def get_ewma_history(runtime: ServerRuntime | None = None) -> dict[str, tuple[float, float]]:
    """Return the runtime EWMA history mapping. Uses global FILE_BATCH_ANALYSIS
    style lazy initialization so tests can call without providing runtime."""
    if runtime is None:
        runtime = _RUNTIME
    try:
        return runtime.ewma_history
    except Exception:
        # fall back to module-level storage for compatibility
        return {}


def _ensure_sessions_dir(path: Path) -> Path:
    try:
        d = path.parent
        d.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    return path


def load_ewma_history(runtime: ServerRuntime | None = None) -> dict:
    """Load persisted EWMA history from disk into runtime. Returns the loaded dict.

    This is best-effort and will not raise on failure.
    """
    if runtime is None:
        runtime = _RUNTIME
    path = runtime.ewma_persist_path
    if not path:
        return runtime.ewma_history
    try:
        _ensure_sessions_dir(path)
        if path.exists():
            import json
            with open(path, 'r', encoding='utf8') as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                # Accept legacy format (value-only) or new (value,timestamp)
                for k,v in data.items():
                    if v is None: continue
                    if isinstance(v,(list,tuple)) and len(v)==2:
                        try: runtime.ewma_history[k] = (float(v[0]), float(v[1]))
                        except Exception: pass
                    else:
                        try: runtime.ewma_history[k] = (float(v), float(os.path.getmtime(path)))
                        except Exception: runtime.ewma_history[k] = (float(v), 0.0)
    except Exception:
        pass
    return runtime.ewma_history


def save_ewma_history(runtime: ServerRuntime | None = None) -> None:
    """Persist the runtime EWMA history to disk. Best-effort; no exception on failure."""
    if runtime is None:
        runtime = _RUNTIME
    path = runtime.ewma_persist_path
    if not path:
        return
    try:
        _ensure_sessions_dir(path)
        import json
        # write atomically
        tmp = path.with_suffix('.tmp')
        with open(tmp, 'w', encoding='utf8') as fh:
            json.dump(runtime.ewma_history, fh)
        tmp.replace(path)
    except Exception:
        pass


def cleanup_ewma_history(runtime: ServerRuntime | None = None, ttl_seconds: int = 86400) -> None:
    """Remove EWMA entries older than ttl_seconds based on stored timestamp."""
    if runtime is None:
        runtime = _RUNTIME
    now = time.time()
    doomed = []
    for k,(val,ts) in list(runtime.ewma_history.items()):
        if ts and (now - ts) > ttl_seconds:
            doomed.append(k)
    for k in doomed:
        runtime.ewma_history.pop(k, None)

# Session persistence helpers
def _current_session_dir() -> Path:
    return Path(os.getenv('SESSION_PERSIST_DIR','data/sessions'))
SESSION_DIR = _current_session_dir()
SESSION_TTL_SECONDS = int(os.getenv('SESSION_TTL_SECONDS','86400') or 86400)

def _ensure_session_dir():
    global SESSION_DIR
    SESSION_DIR = _current_session_dir()
    try: SESSION_DIR.mkdir(parents=True, exist_ok=True)
    except Exception: pass

def persist_session(record: dict) -> None:
    try:
        _ensure_session_dir()
        sid = record.get('session_id')
        if not sid: return
        path = SESSION_DIR / f'{sid}.json'
        import json
        tmp = path.with_suffix('.tmp')
        with open(tmp,'w',encoding='utf8') as fh:
            json.dump(record, fh)
        tmp.replace(path)
    except Exception:
        pass


# ----- Test helpers (guarded by TEST_HELPERS_ENABLED) -----
def _test_helpers_enabled() -> bool:
    return os.getenv('TEST_HELPERS_ENABLED', '0').lower() in {'1', 'true', 'yes'} or 'PYTEST_CURRENT_TEST' in os.environ


def test_helper_reset_quality_manager() -> bool:
    """Reset the global factor-quality manager (test-only). Returns True when performed."""
    if not _test_helpers_enabled():
        return False
    try:
        from src.core.quality.factor_quality import get_quality_manager
        qm = get_quality_manager()
        qm.tp.clear(); qm.fp.clear(); qm.suppressed.clear()
        qm._window.clear(); qm._window_tp = 0; qm._window_fp = 0
        return True
    except Exception:
        return False


def test_helper_inject_event_factors(event: dict) -> bool:
    """Attach synthetic factor keys to an event dict and return True if applied.

    Example: event={'auth_success_count':6} — used by dev/testing flows.
    """
    if not _test_helpers_enabled():
        return False
    try:
        if not isinstance(event, dict):
            return False
        collected: set[str] = set()

        # 1) Call inexpensive synchronous detectors (they observe and/or return factors)
        try:
            from core.detectors.auth_burst import auth_burst_factors
            try:
                collected.update(auth_burst_factors(event) or [])
            except Exception:
                pass
        except Exception:
            pass

        # 2) Run lightweight graph ingest (idempotent, no return but useful for downstream graph-driven lanes)
        try:
            from src.graph.ingest import ingest_event
            try:
                ingest_event(event)
            except Exception:
                pass
        except Exception:
            pass

        # 3) Attempt to run the EventPipeline for a richer set of synthesized factors.
        #    This is best-effort: if async loop management fails, we silently skip.
        try:
            import asyncio
            from src.core.event_pipeline.pipeline import EventPipeline

            # Minimal config shim for the pipeline (pipeline uses cfg_get with defaults)
            class _Cfg:  # simple namespace for required attributes
                pass

            cfg = _Cfg()
            ep = EventPipeline(cfg)

            # If there's an active running loop, use run_coroutine_threadsafe; otherwise use asyncio.run
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            try:
                if loop and loop.is_running():
                    fut = asyncio.run_coroutine_threadsafe(ep.process_event(event), loop)
                    res = fut.result(timeout=5)
                else:
                    res = asyncio.run(ep.process_event(event))
                if res and getattr(res, 'factors', None):
                    collected.update(res.factors or [])
            except Exception:
                # swallow pipeline issues in test helper
                pass
        except Exception:
            pass

        # Attach collected factors back to the event in-place so tests can assert on them.
        if collected:
            try:
                existing = event.get('factors') or []
                if isinstance(existing, list):
                    for f in collected:
                        if f not in existing:
                            existing.append(f)
                    event['factors'] = existing
                else:
                    event['factors'] = list(collected)
            except Exception:
                event['factors'] = list(collected)
            event['injected_factors'] = list(collected)
        else:
            # Still attach an empty list to indicate helper ran
            event.setdefault('injected_factors', [])
        return True
    except Exception:
        return False

# Correlation test helper: enable common rule flags in test context
def test_helper_enable_correlation_flags() -> bool:
    if not _test_helpers_enabled():
        return False
    try:
        import os as _os
        cur = _os.getenv('FEATURE_FLAGS','')
        needed = {'rule_ia_valid_accounts','rule_ext_remote_services'}
        parts = {p.strip() for p in cur.replace(',', ' ').split() if p.strip()}
        parts.update(needed)
        _os.environ['FEATURE_FLAGS'] = ' '.join(sorted(parts))
        return True
    except Exception:
        return False

def load_session(session_id: str) -> dict | None:
    try:
        path = SESSION_DIR / f'{session_id}.json'
        if not path.exists(): return None
        # TTL check
        age = time.time() - path.stat().st_mtime
        if age > SESSION_TTL_SECONDS:
            return None
        import json
        with open(path,'r',encoding='utf8') as fh:
            return json.load(fh)
    except Exception:
        return None

def cleanup_sessions() -> None:
    try:
        if not SESSION_DIR.exists(): return
        now = time.time()
        for p in SESSION_DIR.glob('session-*.json'):
            try:
                if (now - p.stat().st_mtime) > SESSION_TTL_SECONDS:
                    p.unlink(missing_ok=True)
            except Exception:
                pass
    except Exception:
        pass



__all__ = [
    'ServerRuntime',
    'get_server_runtime_state',
    'get_file_hash_factors',
    'get_file_batch_analysis',
    'record_file_event',
    'record_process_event',
    'record_registry_event',
    'record_service_event',
    'record_network_event',
    'ingest_endpoint_events',
]

# Backward compatibility: Provide DECISION_CACHE symbol. Optionally wraps DecisionStore.
try:
    from .decision_store import build_decision_store_from_env, DecisionStore  # type: ignore
    _STORE_ENABLED = os.getenv('DECISION_STORE_ENABLED','1').lower() not in {'0','false','no'}
except Exception:  # pragma: no cover
    build_decision_store_from_env = None  # type: ignore
    DecisionStore = None  # type: ignore
    _STORE_ENABLED = False

if _STORE_ENABLED and build_decision_store_from_env:
    _decision_store = build_decision_store_from_env()
    # Expose underlying mapping-like interface for legacy code expecting dict semantics
    class _DecisionCacheAdapter(dict):  # minimal adapter to mimic dict interface
        """Adapter exposing dict-like access over a DecisionStore instance.

        This adapter intentionally avoids touching private attributes of the
        underlying DecisionStore (such as _data/_order). Instead it calls the
        public store APIs (add/get/remove/clear/keys/items) so the store can
        refactor internals without breaking callers.
        """
        def __init__(self, store):
            super().__init__()
            self._store = store

        def __setitem__(self, k, v):  # type: ignore
            self._store.add(k, v)

        def get(self, k, default=None):  # type: ignore
            val = self._store.get(k)
            return val if val is not None else default

        def values(self):  # type: ignore
            return list(self._store.values())

        def items(self):  # type: ignore
            return list(self._store.items())

        def keys(self):  # type: ignore
            return list(self._store.keys())

        def __contains__(self, k):  # type: ignore
            return self._store.get(k) is not None

        def __getitem__(self, k):  # type: ignore
            val = self._store.get(k)
            if val is None:
                raise KeyError(k)
            return val

        def __iter__(self):  # type: ignore
            # iterate keys in insertion order
            return iter(self._store.keys())

        def pop(self, k, default=None):  # type: ignore
            try:
                val = self._store.remove(k)
                return val if val is not None else default
            except Exception:
                return default

        def __delitem__(self, k):  # type: ignore
            val = self.pop(k)
            if val is None:
                raise KeyError(k)

        def clear(self):  # type: ignore
            self._store.clear()

        def __len__(self):  # type: ignore
            return len(self._store)

    DECISION_CACHE: dict[str, Any] = _DecisionCacheAdapter(_decision_store)
else:
    # Implement a simple thread-safe-ish LRU cache using OrderedDict for Phase 2.
    class _LRUCache(dict):
        def __init__(self, maxsize: int = 5000):
            super().__init__()
            self.maxsize = maxsize
            self._order = OrderedDict()

        def __setitem__(self, k, v):  # type: ignore
            # insert/update ordering
            if k in self._order:
                try:
                    self._order.move_to_end(k)
                except Exception:
                    pass
            else:
                self._order[k] = True
            super().__setitem__(k, v)
            # evict if necessary
            try:
                while len(self._order) > self.maxsize:
                    oldest = next(iter(self._order))
                    self._order.pop(oldest, None)
                    super().pop(oldest, None)
            except Exception:
                pass

        def get(self, k, default=None):  # type: ignore
            v = super().get(k, default)
            if v is not default:
                try:
                    self._order.move_to_end(k)
                except Exception:
                    pass
            return v

        def pop(self, k, default=None):  # type: ignore
            try:
                self._order.pop(k, None)
            except Exception:
                pass
            return super().pop(k, default)

        def clear(self):  # type: ignore
            super().clear()
            try:
                self._order.clear()
            except Exception:
                pass

        def __len__(self):  # type: ignore
            return super().__len__()

    DECISION_CACHE: dict[str, Any] = _LRUCache(maxsize=int(os.getenv('SLO_DECISION_CACHE_MAX', '5000') or 5000))

# -------- Legacy Compatibility Symbols (to be refactored) ---------
import logging
import time

LOGGER = logging.getLogger('runtime')

class _NoOpAgg:
    def __init__(self):
        self.count = 0
    def record(self, *_args, **_kwargs):
        self.count += 1

dns_agg = _NoOpAgg()
asn_stats = _NoOpAgg()

class _NoOpRulesEngine:
    def evaluate_event(self, _event):
        return []
    def score_and_classify(self, _hits):
        return {'verdict': 'OBSERVE', 'score': 0.0}

rules_engine = _NoOpRulesEngine()

# At import time, prefer the real lightweight live.rules_engine when available so
# tests and runtime paths exercise the actual rule logic. Assign the module
# object (which exposes evaluate_event and score_and_classify) to the
# `rules_engine` symbol for compatibility with existing calls.
try:
    import src.live.rules_engine as _real_rules  # type: ignore
    # Only replace if module exposes expected callables
    if hasattr(_real_rules, 'evaluate_event') and hasattr(_real_rules, 'score_and_classify'):
        rules_engine = _real_rules
        LOGGER.debug('runtime_state: wired live.rules_engine as rules_engine')
except Exception:
    # Keep NoOp if real engine not available or import fails
    pass

def _sanitize_event(event: dict, rules: list, classification: dict):  # type: ignore
    sanitized = dict(event)
    sanitized['rules'] = rules
    verdict = classification.get('verdict') if isinstance(classification, dict) else None
    score = classification.get('score') if isinstance(classification, dict) else None
    if verdict is None:
        verdict = 'OBSERVE'
    if score is None:
        score = 0.0
    sanitized['verdict'] = verdict
    sanitized['score'] = score
    # factors optional; if present in classification propagate
    if isinstance(classification, dict) and 'factors' in classification:
        sanitized['factors'] = classification.get('factors') or []
    sanitized['classification'] = classification
    return sanitized

_recent_guardrail_fallback = deque(maxlen=200)
_recent_guardrail_select = deque(maxlen=200)

class _EventQueue:
    def stats(self):
        return {'depth': 0, 'accepted': 0, 'rejected': 0}

# Default in-process event queue instance (fallback)
EVENT_QUEUE = _EventQueue()

# If REDIS_URL is provided, prefer a Redis Streams-backed queue for durability
try:
    REDIS_URL = os.getenv('REDIS_URL')
    if REDIS_URL:
        # import local adapter lazily to avoid hard dependency at import time
        try:
            from src.core.redis_streams import RedisStreamsQueue  # type: ignore

            # STREAM name configurable
            STREAM_NAME = os.getenv('STREAM_INGEST_NAME', 'ingest_stream')
            CONSUMER_GROUP = os.getenv('STREAM_INGEST_GROUP', 'ingest_group')
            # max_size optional hint for backpressure calculations
            STREAM_MAXLEN = int(os.getenv('STREAM_INGEST_MAXLEN', '10000'))

            EVENT_QUEUE = RedisStreamsQueue(redis_url=REDIS_URL, stream_name=STREAM_NAME, group_name=CONSUMER_GROUP, maxlen=STREAM_MAXLEN)
            LOGGER.debug('runtime_state: wired RedisStreamsQueue as EVENT_QUEUE (stream=%s)', STREAM_NAME)
        except Exception:
            LOGGER.exception('Failed to initialize RedisStreamsQueue; falling back to in-memory EVENT_QUEUE')
except Exception:
    # best-effort: keep in-memory queue
    pass

# If still a no-op fallback and Redis not configured, try to bind the
# lightweight in-memory EventQueue so uploads can enqueue events locally.
try:
    if isinstance(EVENT_QUEUE, _EventQueue):
        from src.core.event_queue import EventQueue as _InMemEventQueue  # type: ignore
        EVENT_QUEUE = _InMemEventQueue(max_size=int(os.getenv('EVENT_QUEUE_MAX', '2000') or 2000))
        LOGGER.debug('runtime_state: wired in-memory EventQueue as EVENT_QUEUE')
except Exception:
    # keep no-op fallback
    pass
RECENT_DECISION_WINDOW = 200
GUARDRAIL_HISTORY_SIZE = 200
GUARDRAIL_MIN_SAMPLE = 25

_LITE_DECISION_BUFFER: dict[str, Any] = {}
# Single runtime instance placeholder
_RUNTIME = ServerRuntime()

__all__.extend(['DECISION_CACHE','dns_agg','asn_stats','rules_engine','_sanitize_event','_recent_guardrail_fallback','_recent_guardrail_select','EVENT_QUEUE','RECENT_DECISION_WINDOW','GUARDRAIL_HISTORY_SIZE','GUARDRAIL_MIN_SAMPLE','LOGGER','_RUNTIME'])


def get_decision_cache() -> dict:
    """THE canonical decision cache accessor — resolved at CALL time, never bound at
    import time.

    The dual-instance bug (a confirmed breach written via one path, invisible via
    another) comes from modules doing ``try: from .runtime_state import DECISION_CACHE
    except: DECISION_CACHE = {}`` — the fallback binds a SEPARATE dict when the import
    races a circular load. Call-time resolution via sys.modules sidesteps that window:
    every caller gets the one canonical object that THIS module owns, regardless of
    whether the package was reached as ``api.*`` or ``src.api.*``. Prefer this over
    importing the DECISION_CACHE symbol; it makes the aggregate_decisions 7-path merge
    unnecessary.
    """
    import sys as _sys
    for _name in ('src.api.runtime_state', 'api.runtime_state'):
        _mod = _sys.modules.get(_name)
        if _mod is not None:
            _cache = getattr(_mod, 'DECISION_CACHE', None)
            if _cache is not None:
                return _cache
    # This module is, by definition, loaded when this function runs.
    return DECISION_CACHE


__all__.append('get_decision_cache')


def cache_set(key: str, value: Any) -> None:
    """Normalize and set a value into the canonical DECISION_CACHE.

    If a dict-like value is provided, attempt to coerce into the
    canonical `DecisionRecord` Pydantic model where available. This keeps
    the cache consistent for callers expecting object-like access.
    """
    stored_value = value
    stored = False
    try:
        try:
            from .schemas import DecisionRecord as _DR  # type: ignore
        except Exception:
            _DR = None

        if _DR is not None and isinstance(value, _DR):
            try:
                if hasattr(value, 'model_dump'):
                    stored_value = value.model_dump()
                elif hasattr(value, 'dict'):
                    stored_value = value.dict()
                else:
                    stored_value = dict(getattr(value, '__dict__', {}))
                DECISION_CACHE[key] = stored_value
                stored = True
            except Exception:
                pass

        if not stored and isinstance(value, dict):
            stored_value = value
            DECISION_CACHE[key] = stored_value
            stored = True

        if not stored:
            try:
                stored_value = dict(value)
                DECISION_CACHE[key] = stored_value
                stored = True
            except Exception:
                try:
                    if hasattr(value, 'model_dump'):
                        stored_value = value.model_dump()
                        DECISION_CACHE[key] = stored_value
                        stored = True
                    elif hasattr(value, 'dict'):
                        stored_value = value.dict()
                        DECISION_CACHE[key] = stored_value
                        stored = True
                except Exception:
                    pass
        if not stored:
            try:
                DECISION_CACHE[key] = value
                stored_value = value
                stored = True
            except Exception:
                pass
    except Exception:
        try:
            DECISION_CACHE[key] = value
            stored_value = value
            stored = True
        except Exception:
            pass
    if not stored:
        stored_value = value
    try:
        _LITE_DECISION_BUFFER[key] = stored_value
        if len(_LITE_DECISION_BUFFER) > 512:
            try:
                oldest = next(iter(_LITE_DECISION_BUFFER))
                _LITE_DECISION_BUFFER.pop(oldest, None)
            except Exception:
                _LITE_DECISION_BUFFER.clear()
    except Exception:
        pass


def cache_get(key: str, default: Any = None) -> Any:
    try:
        val = DECISION_CACHE.get(key, default)
    except Exception:
        try:
            val = getattr(DECISION_CACHE, 'get', lambda k, d=None: d)(key, default)
        except Exception:
            return default

    # If we stored plain dicts, some tests expect attribute access (e.g. rec.factors).
    # Wrap plain dicts in an attribute-accessible dict subclass for compatibility.
    try:
        if isinstance(val, dict) and not isinstance(val, _AttrDict):
            return _AttrDict(val)
    except Exception:
        pass
    if (val is None or val is default) and key in _LITE_DECISION_BUFFER:
        val = _LITE_DECISION_BUFFER.get(key)
    return val


def reset_for_tests() -> None:
    """Clear decision cache for testing.

    This helper attempts to clear the DECISION_CACHE in a safe way that
    works whether DECISION_CACHE is a dict-like adapter or a plain mapping.
    """
    try:
        # Prefer clear() if available
        if hasattr(DECISION_CACHE, 'clear'):
            DECISION_CACHE.clear()
            return
        # Fallback: iterate keys and pop
        for k in list(DECISION_CACHE):
            try:
                if hasattr(DECISION_CACHE, 'pop'):
                    DECISION_CACHE.pop(k, None)
                else:
                    del DECISION_CACHE[k]
            except Exception:
                pass
    except Exception:
        pass

    # Best-effort: reset other global singletons used by tests
    try:
        from src.core.dedup.dedup_service import reset_for_tests as _reset_dedup
        try:
            _reset_dedup()
        except Exception:
            pass
    except Exception:
        pass

    # Also clear runtime singleton fields that may leak between tests. This
    # ensures runtime.nx_rate_tracker / asn_tracker and other ephemeral
    # mappings are reset for a clean test environment.
    try:
        # _RUNTIME is the module-level ServerRuntime instance
        try:
            _RUNTIME.nx_rate_tracker.clear()
        except Exception:
            pass
        try:
            if hasattr(_RUNTIME, 'asn_tracker') and _RUNTIME.asn_tracker is not None:
                # prefer clear() when available
                try:
                    _RUNTIME.asn_tracker.clear()
                except Exception:
                    _RUNTIME.asn_tracker = {}
        except Exception:
            pass
        try:
            if hasattr(_RUNTIME, 'file_batch_analysis') and _RUNTIME.file_batch_analysis is not None:
                _RUNTIME.file_batch_analysis.clear()
        except Exception:
            pass
        try:
            if hasattr(_RUNTIME, 'ewma_history') and _RUNTIME.ewma_history is not None:
                _RUNTIME.ewma_history.clear()
        except Exception:
            pass
        try:
            if hasattr(_RUNTIME, 'beacon_scores') and _RUNTIME.beacon_scores is not None:
                _RUNTIME.beacon_scores.clear()
        except Exception:
            pass
        try:
            if hasattr(_RUNTIME, 'dedup_cache') and _RUNTIME.dedup_cache is not None:
                _RUNTIME.dedup_cache.clear()
        except Exception:
            pass
        try:
            # reset nx domain threshold cache to default env value
            _RUNTIME.nx_threshold_cache = float(os.getenv('ZEEK_NXDOMAIN_RATE_THRESHOLD', '0.35') or 0.35)
        except Exception:
            pass
    except Exception:
        pass

    # Clear module-level aliases that mirror runtime state to avoid
    # cross-test visibility of pre-seeded session records or file batch
    # analyses. Tests sometimes seed FILE_BATCH_ANALYSIS at module-level;
    # ensure it's cleared so a fresh runtime is used.
    try:
        global FILE_BATCH_ANALYSIS, FILE_HASH_FACTORS
        FILE_BATCH_ANALYSIS = None
        FILE_HASH_FACTORS = None
    except Exception:
        pass


__all__.extend(['cache_set','cache_get','reset_for_tests'])


def reload_rules_for_tests() -> bool:
    """Test helper: attempt to reload and bind the live.rules_engine to the
    runtime_state.rules_engine symbol. Returns True if a real engine was bound.

    Tests that toggle feature flags or monkeypatch rule sources can call this
    to ensure the runtime uses the latest rules implementation.
    """
    global rules_engine
    try:
        import importlib
        mod = importlib.import_module('src.live.rules_engine')
        # Only bind if expected callables exist
        if hasattr(mod, 'evaluate_event') and hasattr(mod, 'score_and_classify'):
            rules_engine = mod
            LOGGER.debug('runtime_state: reload_rules_for_tests bound live.rules_engine')
            return True
    except Exception:
        pass
    return False


__all__.append('reload_rules_for_tests')

# ------------------------- Test Seeding Helpers -------------------------
def seed_asn_counts(pairs: list[tuple[str,int]]) -> None:
    """Test-only helper: force ASN frequency counts to influence rarity.

    Each pair is (asn, count). We call record() count times. This is intentionally
    lightweight and avoids exposing internal counters directly.
    """
    try:
        from src.live import asn_stats as _asn  # type: ignore
    except Exception:
        return
    for asn, count in pairs:
        try:
            for _ in range(int(count)):
                _asn.record(asn)
        except Exception:
            continue

def seed_dns_nxdomain(host: str, nxd: int, total: int) -> None:
    """Test-only helper: seed DNS NXDOMAIN counts for a host.

    We call dns_agg.record with NXDOMAIN or NOERROR to approximate desired ratios.
    """
    try:
        from src.live import dns_agg as _dns  # type: ignore
    except Exception:
        return
    try:
        # First clear any stale counts by simulating TTL expiry (not directly accessible)
        # Then record events.
        for _ in range(nxd):
            _dns.record(host, 'NXDOMAIN')
        for _ in range(max(0, total - nxd)):
            _dns.record(host, 'NOERROR')
    except Exception:
        pass

__all__.extend(['seed_asn_counts','seed_dns_nxdomain'])


async def _async_drain_event_queue_once(limit: int = 1000, timeout: float = 0.05) -> int:
    """Internal helper: drain up to `limit` events from EVENT_QUEUE calling
    hopgraph ingest for each. Returns number consumed."""
    consumed = 0
    try:
        # Resolve latest module binding so tests that monkeypatch runtime_state see changes
        try:
            from src.core.graph.hopgraph_core import GLOBAL_HOPGRAPH  # type: ignore
        except Exception:
            from src.graph.hopgraph import GLOBAL_HOPGRAPH  # type: ignore
        q = EVENT_QUEUE
        # If queue lacks dequeue, nothing to do
        if not q or not hasattr(q, 'dequeue'):
            return 0
        for _ in range(limit):
            try:
                ev = await q.dequeue(timeout=timeout)
            except Exception:
                ev = None
            if not ev:
                break
            try:
                if isinstance(ev, dict):
                    try:
                        res = GLOBAL_HOPGRAPH.ingest_event(ev, source='stream_ingest')
                        # If the ingest_event is async, await it to avoid un-awaited coroutine warnings
                        if asyncio.iscoroutine(res):
                            await res
                    except Exception:
                        # Best-effort: swallow errors from hopgraph ingestion to keep drain robust in tests
                        pass
            except Exception:
                pass
            consumed += 1
    except Exception:
        return consumed
    return consumed


def drain_event_queue_for_tests(limit: int = 1000, timeout: float = 0.05) -> int:
    """Test helper (sync entrypoint) to drain the in-process EVENT_QUEUE.

    This can be called from tests after performing HTTP requests that
    enqueue events to ensure downstream consumers (like the hopgraph)
    have processed the events synchronously.

    Returns the number of events consumed.
    """
    try:
        import asyncio, importlib, sys as _sys, threading

        # Best-effort: rebind EVENT_QUEUE and DECISION_CACHE to a single canonical runtime_state module
        try:
            # Load the canonical runtime_state module object and then scan
            # sys.modules for any aliases that also expose EVENT_QUEUE or
            # DECISION_CACHE. This is more robust than only checking a single
            # alternate name (some tests import runtime_state under different
            # module names which previously left stale aliases).
            canonical = importlib.import_module('src.api.runtime_state')
            for mod_name, mod in list(_sys.modules.items()):
                try:
                    if mod is None or mod is canonical:
                        continue
                    # Only touch modules that look like runtime_state aliases
                    if not isinstance(mod_name, str):
                        continue
                    if mod_name.endswith('runtime_state') or mod_name.endswith('.runtime_state') or mod_name == 'api.runtime_state':
                        # Align EVENT_QUEUE if present and different
                        if getattr(mod, 'EVENT_QUEUE', None) is not None and getattr(canonical, 'EVENT_QUEUE', None) is not getattr(mod, 'EVENT_QUEUE', None):
                            try:
                                setattr(mod, 'EVENT_QUEUE', getattr(canonical, 'EVENT_QUEUE'))
                            except Exception:
                                pass
                        # Align DECISION_CACHE if present and different
                        if getattr(mod, 'DECISION_CACHE', None) is not None and getattr(canonical, 'DECISION_CACHE', None) is not getattr(mod, 'DECISION_CACHE', None):
                            try:
                                setattr(mod, 'DECISION_CACHE', getattr(canonical, 'DECISION_CACHE'))
                            except Exception:
                                pass
                except Exception:
                    # Best-effort alignment; ignore modules we cannot touch
                    continue
        except Exception:
            pass

        # Try to get the currently running loop in this thread. If one exists,
        # schedule the coroutine onto it using run_coroutine_threadsafe. Otherwise
        # use asyncio.run() for a clean synchronous execution. This avoids
        # creating coroutine objects that might never be awaited in some paths
        # (avoids 'coroutine was never awaited' warnings).
        try:
            running_loop = asyncio.get_running_loop()
        except Exception:
            running_loop = None

        def _attempts_using_running_loop(loop_obj: asyncio.AbstractEventLoop) -> int:
            total = 0
            attempts = 0
            while attempts < 3 and total < limit:
                try:
                    remaining = max(0, limit - total)
                    fut = asyncio.run_coroutine_threadsafe(_async_drain_event_queue_once(limit=remaining, timeout=timeout), loop_obj)
                    # Wait for result with a small timeout to avoid blocking forever
                    batch = fut.result(timeout=max(1.0, timeout * 5))
                    total += int(batch or 0)
                except Exception:
                    break
                attempts += 1
                if batch == 0:
                    try:
                        import time as _t
                        _t.sleep(0.01)
                    except Exception:
                        pass
            return total

        def _attempts_using_asyncio_run() -> int:
            total = 0
            attempts = 0
            while attempts < 3 and total < limit:
                try:
                    remaining = max(0, limit - total)
                    batch = asyncio.run(_async_drain_event_queue_once(limit=remaining, timeout=timeout))
                    total += int(batch or 0)
                except Exception:
                    break
                attempts += 1
                if batch == 0:
                    try:
                        import time as _t
                        _t.sleep(0.01)
                    except Exception:
                        pass
            return total

        if running_loop and running_loop.is_running():
            try:
                return _attempts_using_running_loop(running_loop)
            except Exception:
                return 0
        else:
            try:
                total = _attempts_using_asyncio_run()
                # Best-effort: If integrations XDR worker is present, ensure it had
                # a chance to process its queue. Some tests enqueue into a
                # separate _XDR_EVENT_QUEUE; attempt to start the worker (if
                # available) and poll its recent ingest ring for a short window.
                try:
                    import importlib as _il, time as _t
                    _mod = None
                    try:
                        _mod = _il.import_module('src.api.integrations_endpoints')
                    except Exception:
                        try:
                            _mod = _il.import_module('integrations_endpoints')
                        except Exception:
                            _mod = None
                    if _mod is not None:
                        try:
                            worker = getattr(_mod, '_ensure_worker', None)
                            recent = getattr(_mod, '_RECENT_INGEST', None)
                            if callable(worker):
                                try:
                                    worker()
                                except Exception:
                                    pass
                            # Poll recent ingest ring briefly to allow background
                            # worker to append processed ids.
                            if recent is not None:
                                endt = _t.time() + max(0.2, timeout * 10)
                                while _t.time() < endt:
                                    try:
                                        if len(list(recent)) > 0:
                                            break
                                    except Exception:
                                        pass
                                    _t.sleep(0.01)
                        except Exception:
                            pass
                except Exception:
                    pass
                return total
            except Exception:
                return 0
    except Exception:
        return 0


__all__.append('drain_event_queue_for_tests')

__all__.extend(['cache_set','cache_get'])
