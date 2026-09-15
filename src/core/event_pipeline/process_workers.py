"""Simple process-isolated worker pool helper.

This is a minimal prototype that runs callables in separate processes using
`multiprocessing.Pool.apply_async`. The callable must be picklable; stages
that are not picklable should instead be wrapped into a module-level function.
"""
from __future__ import annotations

from multiprocessing import Pool
from typing import Any, Callable, Optional
import atexit
import time
import threading
import logging
from typing import Dict
import tempfile
import os
import json
from .worker_supervisor import get_supervisor
from .tempfile_manager import register_temp, unregister_temp


_POOL: Optional[Pool] = None
_POOL_START_TS: float | None = None
_POOL_LOCK = threading.Lock()
_POOL_LAST_ERROR: str | None = None
_POOL_RESTARTS = 0
_HEALTHY = True
_LOGGER = logging.getLogger(__name__)


def get_pool(processes: int = 2) -> Pool:
    global _POOL
    if _POOL is None:
        with _POOL_LOCK:
            if _POOL is None:
                _POOL = Pool(processes=processes)
                atexit.register(_pool_terminate)
                global _POOL_START_TS, _POOL_RESTARTS, _HEALTHY
                _POOL_START_TS = time.time()
                _POOL_RESTARTS = 0
                _HEALTHY = True
                try:
                    from src.core.event_pipeline.metrics import PipelineMetrics
                    PipelineMetrics().set_pool_health(_POOL_RESTARTS, False, True)
                except Exception:
                    pass
    return _POOL


def submit_to_supervisor(fn: Callable[..., Any], *args, timeout: float | None = None) -> Any:
    """Submit to the lightweight WorkerSupervisor instead of multiprocessing.Pool.

    This is used as the preferred path for process isolation to gain heartbeat
    and restart behavior while still supporting simple sync callables.
    """
    try:
        import os
        if os.getenv('ENABLE_SUPERVISOR','0').lower() in {'1', 'true', 'yes'}:
            # Provide a default warmup that tries to import heavy packet libs in workers
            def _warmup():
                try:
                    import scapy.all as scapy
                except Exception:
                    pass
                try:
                    import dpkt
                except Exception:
                    pass
            sup = get_supervisor(warmup_fn=_warmup)
            return sup.submit(fn, args, timeout=timeout)
        # Supervisor disabled by env - fall back to process pool
        return run_in_process(fn, *args, timeout=timeout)
    except Exception:
        # Final fallback to pool if supervisor fails
        return run_in_process(fn, *args, timeout=timeout)


def _pool_terminate() -> None:
    global _POOL
    try:
        if _POOL:
            _POOL.terminate()
            _POOL.join()
    finally:
        _POOL = None
        global _POOL_START_TS, _POOL_LAST_ERROR, _POOL_RESTARTS, _HEALTHY
        _POOL_START_TS = None
        _POOL_LAST_ERROR = None
        _POOL_RESTARTS = 0
        _HEALTHY = False
        try:
            from src.core.event_pipeline.metrics import PipelineMetrics
            PipelineMetrics().set_pool_health(_POOL_RESTARTS, False, False)
        except Exception:
            pass


def run_in_process(fn: Callable[..., Any], *args, timeout: float | None = None) -> Any:
    pool = get_pool()
    res = pool.apply_async(fn, args)
    try:
        return res.get(timeout=timeout)
    except Exception as exc:
        # Capture the error and avoid raising across process boundary
        global _POOL_LAST_ERROR, _HEALTHY
        _POOL_LAST_ERROR = str(exc)
        _HEALTHY = False
        _LOGGER.warning('Worker process raised an exception: %s', _POOL_LAST_ERROR)
        try:
            from src.core.event_pipeline.metrics import PipelineMetrics
            PipelineMetrics().set_pool_health(_POOL_RESTARTS or 0, True, False)
        except Exception:
            pass
        return {'_error': _POOL_LAST_ERROR}


def pool_health() -> Dict[str, Any]:
    """Return simple health info about the pool for metrics and inspection."""
    return {
        'started_at': _POOL_START_TS,
        'restarts': _POOL_RESTARTS,
        'last_error': _POOL_LAST_ERROR,
        'healthy': _HEALTHY,
    }


def restart_pool() -> None:
    """Attempt to terminate and recreate the pool. Non-blocking best-effort."""
    global _POOL_RESTARTS, _POOL_LAST_ERROR, _HEALTHY
    try:
        _pool_terminate()
    except Exception as exc:
        _POOL_LAST_ERROR = str(exc)
        _HEALTHY = False
    try:
        get_pool()
        _POOL_RESTARTS = (_POOL_RESTARTS or 0) + 1
        _HEALTHY = True
        try:
            from src.core.event_pipeline.metrics import PipelineMetrics
            PipelineMetrics().set_pool_health(_POOL_RESTARTS or 0, False, True)
        except Exception:
            pass
    except Exception as exc:
        _POOL_LAST_ERROR = str(exc)
        _HEALTHY = False


def execute_stage_runner(module_path: str, func_name: str, event: dict, ctx_state: dict | None = None) -> dict:
    """Top-level executor that imports a module and runs a stage runner.

    This is intentionally a top-level function so it can be pickled and sent
    to worker processes. It will import the target module, call the named
    function (async-aware) and return a serializable dict describing the
    StageResult.
    """
    import importlib
    import asyncio
    from types import SimpleNamespace

    module = importlib.import_module(module_path)
    func = getattr(module, func_name)

    # Build a minimal context object; heavy stages should tolerate a simple
    # ctx with only `state` available. Avoid passing complex objects.
    ctx = SimpleNamespace(config=None, registry=None, logger=None, state=ctx_state or {})

    # Support sync or async callables
    if asyncio.iscoroutinefunction(func):
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(func(event, ctx))
        finally:
            try:
                loop.close()
            finally:
                try:
                    asyncio.set_event_loop(None)
                except Exception:
                    pass
    else:
        result = func(event, ctx)
        if asyncio.iscoroutine(result):
            loop = asyncio.new_event_loop()
            try:
                asyncio.set_event_loop(loop)
                result = loop.run_until_complete(result)
            finally:
                try:
                    loop.close()
                finally:
                    try:
                        asyncio.set_event_loop(None)
                    except Exception:
                        pass

    # Normalize result into a serializable dict
    try:
        name = getattr(result, 'name', func_name)
        factors = getattr(result, 'factors', []) or []
        confidence_delta = float(getattr(result, 'confidence_delta', 0.0) or 0.0)
        terminal = bool(getattr(result, 'terminal', False))
        duration_ms = float(getattr(result, 'duration_ms', 0.0) or 0.0)
        metadata = getattr(result, 'metadata', None)
        return {
            'name': name,
            'factors': factors,
            'confidence_delta': confidence_delta,
            'terminal': terminal,
            'duration_ms': duration_ms,
            'metadata': metadata,
        }
    except Exception:
        # Fallback: attempt unpacking as a tuple
        try:
            factors, delta, terminal, metadata = result  # type: ignore[misc]
            return {
                'name': func_name,
                'factors': list(factors or []),
                'confidence_delta': float(delta or 0.0),
                'terminal': bool(terminal),
                'duration_ms': 0.0,
                'metadata': metadata,
            }
        except Exception:
            return {'name': func_name, 'factors': [], 'confidence_delta': 0.0, 'terminal': False, 'duration_ms': 0.0, 'metadata': {'error': 'unserializable_result'}}


def prepare_blob_for_worker(event: dict, blob_key: str = 'pcap_blob') -> dict:
    """If `event[blob_key]` contains large bytes, write to a temp file and
    return a lightweight event dict with `pcap_path` pointing to the temp file.
    Otherwise return the original event.
    """
    blob = event.get(blob_key)
    if not blob or not isinstance(blob, (bytes, bytearray)):
        return event
    # If blob is small (<1MB) we can inline it; otherwise write to temp file
    try:
        if len(blob) < 1024 * 1024:
            return event
    except Exception:
        return event
    try:
        fd, path = tempfile.mkstemp(prefix='threat_pcap_', suffix='.pcap')
        with os.fdopen(fd, 'wb') as fh:
            fh.write(blob)
        try:
            register_temp(path)
        except Exception:
            pass
        new_event = dict(event)
        new_event.pop(blob_key, None)
        new_event['pcap_path'] = path
        return new_event
    except Exception:
        return event
