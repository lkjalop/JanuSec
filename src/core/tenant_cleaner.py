import os
import threading
import time
from typing import Optional

from src.core.tenant_store import prune_inactive_tenants

_THREAD: Optional[threading.Thread] = None
_STOP = threading.Event()

def _run_loop(interval: float) -> None:
    while not _STOP.wait(interval):
        try:
            prune_inactive_tenants()
        except Exception:
            pass

def start_tenant_cleaner(interval_seconds: int | None = None) -> None:
    global _THREAD, _STOP
    if _THREAD and _THREAD.is_alive():
        return
    try:
        ival = int(interval_seconds if interval_seconds is not None else os.getenv('TENANT_CLEAN_INTERVAL_SECONDS', '0'))
    except Exception:
        ival = 0
    if ival <= 0:
        return
    _STOP.clear()
    _THREAD = threading.Thread(target=_run_loop, args=(ival,), daemon=True)
    _THREAD.start()

def stop_tenant_cleaner() -> None:
    global _THREAD, _STOP
    _STOP.set()
    if _THREAD:
        try:
            _THREAD.join(timeout=2.0)
        except Exception:
            pass
    _THREAD = None
