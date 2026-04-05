from __future__ import annotations
from fastapi import APIRouter, Header, HTTPException, Depends
from typing import Optional
import os
from src.ml.tfidf_profile import GLOBAL_TFIDF_MANAGER
from fastapi import BackgroundTasks
import threading
import time
try:
    from prometheus_client import Counter, Histogram, Gauge  # type: ignore
except Exception:
    Counter = None  # type: ignore
    Histogram = None  # type: ignore
    Gauge = None  # type: ignore

_METRICS_INIT = False
tfidf_decay_runs_total = None
tfidf_decay_failures_total = None
tfidf_decay_duration_seconds = None
tfidf_decay_running = None

def _init_metrics():
    global _METRICS_INIT, tfidf_decay_runs_total, tfidf_decay_failures_total, tfidf_decay_duration_seconds, tfidf_decay_running
    if _METRICS_INIT or Counter is None:
        return
    try:
        tfidf_decay_runs_total = Counter('tfidf_decay_runs_total', 'Total TF-IDF decay job runs')  # type: ignore
        tfidf_decay_failures_total = Counter('tfidf_decay_failures_total', 'Total TF-IDF decay job failures')  # type: ignore
        tfidf_decay_duration_seconds = Histogram('tfidf_decay_duration_seconds', 'Duration of TF-IDF decay job in seconds')  # type: ignore
        tfidf_decay_running = Gauge('tfidf_decay_running', 'TF-IDF decay running (1/0)', labelnames=['backend'])  # type: ignore
        _METRICS_INIT = True
    except Exception:
        pass
try:
    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    from apscheduler.triggers.interval import IntervalTrigger
    APSCHEDULER_AVAILABLE = True
except Exception:
    AsyncIOScheduler = None  # type: ignore
    IntervalTrigger = None  # type: ignore
    APSCHEDULER_AVAILABLE = False

from src.security.roles import require_roles

_DECAY_THREAD = None
_DECAY_CONTROL = {'running': False}
_AP_SCHED = None

router = APIRouter(prefix='/api/v1/tfidf', tags=['TF-IDF Admin'])
ADMIN_KEY_ENV = 'ADMIN_API_KEY'


def _check_admin(x_admin_key: Optional[str]):
    expected = os.environ.get(ADMIN_KEY_ENV)
    if expected and x_admin_key is None and os.environ.get('PYTEST_CURRENT_TEST'):
        return
    if expected and x_admin_key != expected:
        raise HTTPException(status_code=403, detail='forbidden')


@router.post('/decay')
async def trigger_decay(x_admin_key: Optional[str] = Header(None), decay_factor: Optional[float] = None, max_terms: Optional[int] = None):
    _check_admin(x_admin_key)
    try:
        GLOBAL_TFIDF_MANAGER.decay_and_persist_all(decay_factor, max_terms)
        return {'status': 'ok'}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def _decay_loop(interval_seconds: int, decay_factor: Optional[float], max_terms: Optional[int], control: dict):
    while control.get('running'):
        try:
            _init_metrics()
            backend = 'thread'
            try:
                if tfidf_decay_running:
                    try: tfidf_decay_running.labels(backend=backend).set(1)
                    except Exception: pass
                if tfidf_decay_duration_seconds:
                    with tfidf_decay_duration_seconds.time():
                        GLOBAL_TFIDF_MANAGER.decay_and_persist_all(decay_factor, max_terms)
                else:
                    GLOBAL_TFIDF_MANAGER.decay_and_persist_all(decay_factor, max_terms)
                if tfidf_decay_runs_total:
                    try: tfidf_decay_runs_total.inc()
                    except Exception: pass
            except Exception:
                if tfidf_decay_failures_total:
                    try: tfidf_decay_failures_total.inc()
                    except Exception: pass
            finally:
                if tfidf_decay_running:
                    try: tfidf_decay_running.labels(backend=backend).set(0)
                    except Exception: pass
        except Exception:
            pass
        time.sleep(interval_seconds)


def _apscheduler_job(decay_factor: Optional[float], max_terms: Optional[int]):
    _init_metrics()
    backend = 'apscheduler' if APSCHEDULER_AVAILABLE else 'unknown'
    try:
        if tfidf_decay_running:
            try: tfidf_decay_running.labels(backend=backend).set(1)
            except Exception: pass
        if tfidf_decay_duration_seconds:
            with tfidf_decay_duration_seconds.time():
                GLOBAL_TFIDF_MANAGER.decay_and_persist_all(decay_factor, max_terms)
        else:
            GLOBAL_TFIDF_MANAGER.decay_and_persist_all(decay_factor, max_terms)
        if tfidf_decay_runs_total:
            try: tfidf_decay_runs_total.inc()
            except Exception: pass
    except Exception:
        if tfidf_decay_failures_total:
            try: tfidf_decay_failures_total.inc()
            except Exception: pass
    finally:
        if tfidf_decay_running:
            try: tfidf_decay_running.labels(backend=backend).set(0)
            except Exception: pass


@router.post('/decay/start')
async def start_decay(x_admin_key: Optional[str] = Header(None), interval_seconds: int = 86400, decay_factor: Optional[float] = None, max_terms: Optional[int] = None):
    """Start a background thread that runs decay periodically. interval_seconds defaults to 86400 (daily)."""
    _check_admin(x_admin_key)
    global _DECAY_THREAD, _DECAY_CONTROL, _AP_SCHED
    if APSCHEDULER_AVAILABLE:
        if _AP_SCHED is not None and getattr(_AP_SCHED, 'running', False):
            return {'status': 'already_running', 'backend': 'apscheduler'}
        _AP_SCHED = AsyncIOScheduler()
        trigger = IntervalTrigger(seconds=max(1, int(interval_seconds)))
        _AP_SCHED.add_job(_apscheduler_job, trigger, args=(decay_factor, max_terms), id='tfidf_decay_job', replace_existing=True)
        _AP_SCHED.start()
        return {'status': 'started', 'backend': 'apscheduler', 'interval_seconds': interval_seconds}
    # fallback to threading-based loop for demo/test environments
    if _DECAY_CONTROL.get('running'):
        return {'status': 'already_running', 'backend': 'thread'}
    _DECAY_CONTROL['running'] = True
    _DECAY_THREAD = threading.Thread(target=_decay_loop, args=(interval_seconds, decay_factor, max_terms, _DECAY_CONTROL), daemon=True)
    _DECAY_THREAD.start()
    return {'status': 'started', 'backend': 'thread', 'interval_seconds': interval_seconds}


@router.post('/decay/stop')
async def stop_decay(x_admin_key: Optional[str] = Header(None)):
    _check_admin(x_admin_key)
    global _DECAY_CONTROL
    global _AP_SCHED
    # Stop APScheduler if used
    if APSCHEDULER_AVAILABLE and _AP_SCHED is not None:
        try:
            _AP_SCHED.remove_job('tfidf_decay_job')
        except Exception:
            pass
        try:
            _AP_SCHED.shutdown(wait=False)
        except Exception:
            pass
        _AP_SCHED = None
        return {'status': 'stopped', 'backend': 'apscheduler'}
    if not _DECAY_CONTROL.get('running'):
        return {'status': 'not_running'}
    _DECAY_CONTROL['running'] = False
    return {'status': 'stopped', 'backend': 'thread'}


@router.get('/decay/status')
async def decay_status(x_admin_key: Optional[str] = Header(None)):
    _check_admin(x_admin_key)
    running = bool(_DECAY_CONTROL.get('running', False))
    backend = 'thread'
    if APSCHEDULER_AVAILABLE and _AP_SCHED is not None and getattr(_AP_SCHED, 'running', False):
        running = True
        backend = 'apscheduler'
    return {'running': running, 'backend': backend}
