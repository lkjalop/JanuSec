"""Lightweight worker supervisor with heartbeat and warmup.

This module provides a simple process manager that spawns a pool of worker
processes using multiprocessing.Process and a task queue. It offers a
compatible API surface to `process_workers` callers: `submit(fn, args, timeout)`
and `restart()` plus health introspection. The implementation favors clarity
and restart-on-failure with simple heartbeats.
"""
from __future__ import annotations

import multiprocessing as mp
import threading
import atexit
import time
import queue
import traceback
import os
from typing import Any, Callable, Dict, Optional
from src.core.event_pipeline.metrics import PipelineMetrics


class _Worker(mp.Process):
    def __init__(self, task_q: mp.Queue, result_q: mp.Queue, heartbeat_q: mp.Queue, warmup_fn: Optional[Callable] = None):
        super().__init__()
        self.task_q = task_q
        self.result_q = result_q
        self.heartbeat_q = heartbeat_q
        self.warmup_fn = warmup_fn

    def run(self):
        # Warmup hook: import heavy libs here to reduce latency on first task
        try:
            if self.warmup_fn:
                try:
                    self.warmup_fn()
                except Exception:
                    pass
        except Exception:
            pass
        # Loop reading tasks
        while True:
            try:
                item = self.task_q.get()
                if item is None:
                    break
                fn, args, task_id = item
                # support a lightweight probe marker to emit heartbeat without calling a fn
                if fn == '__emit_hb__':
                    try:
                        self.heartbeat_q.put({'pid': self.pid, 'ts': time.time()})
                    except Exception:
                        pass
                    continue
                # send heartbeat
                try:
                    self.heartbeat_q.put({'pid': self.pid, 'ts': time.time()})
                except Exception:
                    pass
                try:
                    t0 = time.time()
                    res = fn(*args)
                    dur = (time.time() - t0) * 1000.0
                    # include pid in result for supervisor metrics
                    self.result_q.put((task_id, True, res, self.pid, dur))
                except Exception:
                    tb = traceback.format_exc()
                    self.result_q.put((task_id, False, tb, self.pid, 0.0))
            except EOFError:
                break
            except Exception:
                continue


class WorkerSupervisor:
    def __init__(self, processes: int = 2, warmup_fn: Optional[Callable] = None, heartbeat_interval: float = 5.0):
        self.processes = max(1, int(processes or 2))
        self.task_q: mp.Queue = mp.Queue()
        self.result_q: mp.Queue = mp.Queue()
        self.heartbeat_q: mp.Queue = mp.Queue()
        self.workers: list[_Worker] = []
        self._task_counter = 0
        self._pending: Dict[int, queue.Queue] = {}
        self._lock = threading.Lock()
        self.warmup_fn = warmup_fn
        self.heartbeat_interval = float(heartbeat_interval)
        self._last_hb: Dict[int, float] = {}
        self._restart_attempts: Dict[int, int] = {}
        # Read backoff config from env to make behavior configurable
        try:
            self._backoff_base = float(os.getenv('SUPERVISOR_BACKOFF_BASE', '1.0'))
        except Exception:
            self._backoff_base = 1.0
        try:
            self._backoff_cap = float(os.getenv('SUPERVISOR_BACKOFF_CAP', '30.0'))
        except Exception:
            self._backoff_cap = 30.0
        try:
            self._restart_max_attempts = int(os.getenv('SUPERVISOR_RESTART_MAX_ATTEMPTS_PER_WORKER', '5'))
        except Exception:
            self._restart_max_attempts = 5
        self._start_workers()
        self._watcher = threading.Thread(target=self._watch_loop, daemon=True)
        self._watcher.start()

    def _start_workers(self):
        for _ in range(self.processes):
            w = _Worker(self.task_q, self.result_q, self.heartbeat_q, warmup_fn=self.warmup_fn)
            w.daemon = True
            w.start()
            self.workers.append(w)

    def _watch_loop(self):
        # Reap results and route to pending queues
        last_probe = time.time()
        while True:
            try:
                item = self.result_q.get(timeout=1)
                # result tuple format: (tid, ok, payload, pid, duration_ms)
                if isinstance(item, tuple) and len(item) >= 5:
                    tid, ok, payload, pid, duration_ms = item[:5]
                else:
                    # backwards-compatible fallback
                    tid, ok, payload = item
                    pid = None
                    duration_ms = None
                q = None
                with self._lock:
                    q = self._pending.pop(tid, None)
                if q:
                    q.put((ok, payload))
                # update heartbeat map and metrics if we have pid/duration
                try:
                    now = time.time()
                    if pid:
                        self._last_hb[pid] = now
                        try:
                            PipelineMetrics().set_worker_metrics(pid=pid, last_heartbeat_ts=now, task_latency_ms=duration_ms if duration_ms is not None else None, failed=(not ok))
                        except Exception:
                            pass
                except Exception:
                    pass
            except queue.Empty:
                pass
            except Exception:
                pass

            # Drain heartbeat queue (separate channel) to update metrics immediately
            try:
                while True:
                    try:
                        hb = self.heartbeat_q.get_nowait()
                    except Exception:
                        break
                    try:
                        pid = hb.get('pid')
                        ts = hb.get('ts', time.time())
                        self._last_hb[pid] = ts
                        try:
                            PipelineMetrics().set_worker_metrics(pid=pid, last_heartbeat_ts=ts)
                        except Exception:
                            pass
                    except Exception:
                        pass
            except Exception:
                pass

            # Periodically probe heartbeats and restart dead workers
            try:
                now = time.time()
                if now - last_probe > max(1.0, self.heartbeat_interval):
                    self._probe_and_restart(now)
                    last_probe = now
            except Exception:
                pass

    def _probe_and_restart(self, now: float):
        # send a lightweight probe by asking workers to emit heartbeat
        try:
            for _ in range(self.processes):
                try:
                    # a probe task that only triggers heartbeat put in worker; use a
                    # picklable marker value so it can be sent across process boundary
                    self.task_q.put(('__emit_hb__', (), 0))
                except Exception:
                    pass
        except Exception:
            pass
        # allow small delay for heartbeat propagation
        time.sleep(0.05)
        for w in list(self.workers):
            pid = getattr(w, 'pid', None)
            last = self._last_hb.get(pid, 0)
            if now - last > (self.heartbeat_interval * 2):
                # restart worker with exponential backoff, cap attempts per worker
                attempts = self._restart_attempts.get(pid, 0) + 1
                self._restart_attempts[pid] = attempts
                if self._restart_max_attempts and attempts > self._restart_max_attempts:
                    # mark worker as failed and do not restart
                    try:
                        PipelineMetrics().set_worker_metrics(pid=pid, last_heartbeat_ts=last, failed=True)
                    except Exception:
                        pass
                    try:
                        w.terminate()
                    except Exception:
                        pass
                    try:
                        self.workers.remove(w)
                    except Exception:
                        pass
                    continue
                backoff = min(self._backoff_base * (2 ** (attempts - 1)), self._backoff_cap)
                try:
                    w.terminate()
                except Exception:
                    pass
                try:
                    self.workers.remove(w)
                except Exception:
                    pass
                time.sleep(backoff)
                nw = _Worker(self.task_q, self.result_q, self.heartbeat_q, warmup_fn=self.warmup_fn)
                nw.daemon = True
                nw.start()
                self.workers.append(nw)
                self._last_hb[getattr(nw, 'pid', 0)] = time.time()
                try:
                    PipelineMetrics().set_worker_metrics(pid=getattr(nw, 'pid', 0), last_heartbeat_ts=time.time())
                except Exception:
                    pass

    def submit(self, fn: Callable[..., Any], args: tuple[Any, ...], timeout: Optional[float] = None):
        with self._lock:
            self._task_counter += 1
            tid = self._task_counter
            q = queue.Queue()
            self._pending[tid] = q
        # record in-flight before dispatch
        try:
            # supervisor doesn't know which worker will pick up; increment a global placeholder pid='pool'
            PipelineMetrics().inc_inflight('pool')
        except Exception:
            pass
        self.task_q.put((fn, args, tid))
        try:
            ok, payload = q.get(timeout=timeout)
        except Exception as exc:
            # Timeout or other error
            with self._lock:
                self._pending.pop(tid, None)
            try:
                PipelineMetrics().dec_inflight('pool')
            except Exception:
                pass
            raise
        # On successful receipt, decrement inflight and update metrics if pid info available in pending
        try:
            PipelineMetrics().dec_inflight('pool')
        except Exception:
            pass
        if ok:
            return payload
        raise RuntimeError(payload)

    def restart(self):
        # Terminate workers and restart them
        try:
            # send sentinels to workers to ask them to exit
            for _ in self.workers:
                try:
                    self.task_q.put(None)
                except Exception:
                    pass
            for w in self.workers:
                try:
                    w.join(timeout=2)
                except Exception:
                    pass
            self.workers = []
            self._start_workers()
        except Exception:
            pass

    def shutdown(self):
        # Best-effort shutdown called at process exit
        try:
            for _ in list(self.workers):
                try:
                    self.task_q.put(None)
                except Exception:
                    pass
            for w in list(self.workers):
                try:
                    w.join(timeout=2)
                except Exception:
                    pass
        except Exception:
            pass

    def health(self):
        return {
            'worker_count': len(self.workers),
            'pending_tasks': len(self._pending),
        }


# Module-level singleton
_SUPERVISOR: Optional[WorkerSupervisor] = None


def get_supervisor(processes: int = 2, warmup_fn: Optional[Callable] = None) -> WorkerSupervisor:
    global _SUPERVISOR
    if _SUPERVISOR is None:
        _SUPERVISOR = WorkerSupervisor(processes=processes, warmup_fn=warmup_fn)
        try:
            atexit.register(_SUPERVISOR.shutdown)
        except Exception:
            pass
    else:
        # If a warmup_fn is provided after the singleton exists, try to set it
        try:
            if warmup_fn is not None:
                _SUPERVISOR.warmup_fn = warmup_fn
        except Exception:
            pass
    return _SUPERVISOR


def reset_supervisor() -> None:
    """Test/helper utility: shutdown and clear the module-level supervisor singleton."""
    global _SUPERVISOR
    try:
        if _SUPERVISOR is not None:
            try:
                _SUPERVISOR.shutdown()
            except Exception:
                pass
    except Exception:
        pass
    _SUPERVISOR = None
