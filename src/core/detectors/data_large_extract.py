"""EWMA-based data large extract detector.

Tracks EWMA mean and variance per source (e.g., ip or user) and emits 'data:large_extract'
when a single event's bytes_out exceeds mean + K * stddev or a configured absolute threshold.

This module persists EWMA state to disk (best-effort) to survive restarts. The
path is controlled by DATA_EWMA_STATE_PATH and defaults to `data/ewma_state.json`.
"""
from __future__ import annotations
import time, math, json, os, threading
from typing import Optional
from src.core.factors.emission_tracker import record_emission

# In-memory EWMA state per source
_STATE: dict[str, dict] = {}
_LOCK = threading.RLock()
_STATE_PATH = os.getenv('DATA_EWMA_STATE_PATH', 'data/ewma_state.json')
ALPHA = float(os.getenv('DATA_EWMA_ALPHA', '0.3'))
K_STD = float(os.getenv('DATA_EWMA_K', '2.0'))
ABS_THRESHOLD = int(os.getenv('DATA_EWMA_ABS_THRESHOLD', str(5_000_000)))
SAVE_INTERVAL = int(os.getenv('DATA_EWMA_SAVE_INTERVAL', '30') or 30)

_SAVE_THREAD = None
_SAVE_THREAD_STARTED = False


def _init_state(key: str):
    _STATE[key] = {'ewma': 0.0, 'ewma_var': 0.0, 'count': 0, 'last_ts': 0.0}


def _load_state():
    try:
        if os.path.exists(_STATE_PATH):
            with open(_STATE_PATH, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
            # convert numeric strings to numbers if needed
            with _LOCK:
                for k, v in data.items():
                    try:
                        _STATE[k] = {
                            'ewma': float(v.get('ewma', 0.0)),
                            'ewma_var': float(v.get('ewma_var', 0.0)),
                            'count': int(v.get('count', 0)),
                            'last_ts': float(v.get('last_ts', 0.0)),
                        }
                    except Exception:
                        continue
    except Exception:
        # best-effort: ignore failures
        pass


def _save_state():
    try:
        d = {}
        with _LOCK:
            for k, v in _STATE.items():
                d[k] = {
                    'ewma': float(v.get('ewma', 0.0)),
                    'ewma_var': float(v.get('ewma_var', 0.0)),
                    'count': int(v.get('count', 0)),
                    'last_ts': float(v.get('last_ts', 0.0)),
                }
        os.makedirs(os.path.dirname(_STATE_PATH) or '.', exist_ok=True)
        tmp = _STATE_PATH + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as fh:
            json.dump(d, fh)
        # Atomic replace
        try:
            os.replace(tmp, _STATE_PATH)
        except Exception:
            # fallback to rename
            try:
                os.rename(tmp, _STATE_PATH)
            except Exception:
                pass
    except Exception:
        pass


def _save_loop():
    global _SAVE_THREAD_STARTED
    _SAVE_THREAD_STARTED = True
    try:
        while True:
            try:
                # Persist state then sleep. Respect TEST_LOOP_INTERVAL when set
                try:
                    _save_state()
                except Exception:
                    pass
                try:
                    if os.getenv('FAST_TEST_MODE', '').lower() in {'1', 'true', 'yes'} or os.getenv('PYTEST_CURRENT_TEST'):
                        sleep_for = float(os.getenv('TEST_LOOP_INTERVAL') or 0.1)
                    else:
                        tsi = int(os.getenv('TEST_LOOP_INTERVAL') or 0)
                        if tsi > 0:
                            sleep_for = max(0.1, min(tsi, max(1, SAVE_INTERVAL)))
                        else:
                            sleep_for = max(1, SAVE_INTERVAL)
                except Exception:
                    sleep_for = max(1, SAVE_INTERVAL)
                time.sleep(sleep_for)
            except Exception:
                try:
                    time.sleep(max(0.1, SAVE_INTERVAL))
                except Exception:
                    time.sleep(1)
    except Exception:
        pass


def _ensure_save_thread():
    global _SAVE_THREAD
    # Avoid starting background save thread during unit tests
    if os.getenv('FAST_TEST_MODE', '').lower() in {'1', 'true', 'yes'} or os.getenv('PYTEST_CURRENT_TEST'):
        return
    if _SAVE_THREAD is None or not _SAVE_THREAD.is_alive():
        import threading
        if not (os.getenv('FAST_TEST_MODE', '').lower() in {'1', 'true', 'yes'} or os.getenv('PYTEST_CURRENT_TEST')):
            _SAVE_THREAD = threading.Thread(target=_save_loop, daemon=True)
            _SAVE_THREAD.start()


def check_and_emit(hopgraph, source: str, bytes_out: int, now: Optional[float] = None) -> bool:
    """Update EWMA for source and emit if event is anomalous."""
    if not source:
        return False
    now = now or time.time()
    with _LOCK:
        st = _STATE.get(source)
        if st is None:
            _init_state(source)
            st = _STATE[source]

        # Use prior mean/variance to compute detection threshold so a single
        # extreme sample doesn't inflate variance and mask the anomaly.
        prev_mean = st['ewma']
        var_prev = st['ewma_var']
        if st['count'] == 0:
            # initialize state, do not emit on first sample
            st['ewma'] = float(bytes_out)
            st['ewma_var'] = 0.0
            st['count'] = 1
            st['last_ts'] = now
            try:
                _save_state()
            except Exception:
                pass
            return False

        std_prev = math.sqrt(max(0.0, var_prev))
        threshold = max(ABS_THRESHOLD, prev_mean + K_STD * std_prev, prev_mean * 3.0)
        if float(bytes_out) > threshold:
            node = source
            try:
                hopgraph.add_node_factor(node, 'data:large_extract')
            except Exception:
                pass
            try:
                record_emission('data:large_extract', decision_id=None, node_ids=[node])
            except Exception:
                pass
            # After emitting, still update EWMA state with the new sample
            alpha = ALPHA
            mean_new = alpha * float(bytes_out) + (1 - alpha) * prev_mean
            var_new = alpha * ((float(bytes_out) - mean_new) ** 2) + (1 - alpha) * var_prev
            st['ewma'] = mean_new
            st['ewma_var'] = var_new
            st['count'] += 1
            st['last_ts'] = now
            try:
                _save_state()
            except Exception:
                pass
            return True

        # No emission: update EWMA normally and return False
        alpha = ALPHA
        mean_new = alpha * float(bytes_out) + (1 - alpha) * prev_mean
        var_new = alpha * ((float(bytes_out) - mean_new) ** 2) + (1 - alpha) * var_prev
        st['ewma'] = mean_new
        st['ewma_var'] = var_new
        st['count'] += 1
        st['last_ts'] = now
        try:
            _save_state()
        except Exception:
            pass
        return False


_load_state()
try:
    _ensure_save_thread()
except Exception:
    pass

__all__ = ['check_and_emit']
