"""Simple structured audit event emitter.

Writes newline-delimited JSON (JSONL) to a configured file (audits/audit_events.jsonl)
and emits to stdout for container log aggregation. Events are best-effort and should
never block request handling.
"""
from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Dict

_AUDIT_PATH = os.getenv('AUDIT_JSONL_PATH', 'audits/audit_events.jsonl')

_lock = threading.Lock()


def _safe_write(line: str) -> None:
    try:
        os.makedirs(os.path.dirname(_AUDIT_PATH), exist_ok=True)
        with _lock:
            with open(_AUDIT_PATH, 'a', encoding='utf-8') as fh:
                fh.write(line + '\n')
    except Exception:
        # best-effort; swallow
        pass


def emit(event_type: str, user: dict | None, payload: Dict[str, Any]) -> None:
    evt = {
        'ts': time.time(),
        'event_type': event_type,
        'user': user or {},
        'payload': payload,
    }
    line = json.dumps(evt, default=str)
    # Write to stdout for centralized logging
    try:
        print(line)
    except Exception:
        pass
    # Persist to file (best-effort)
    _safe_write(line)


def canonical_user(request: Any | None = None, auth: Any | None = None) -> dict:
    """Produce a canonical user dict from available auth sources.

    Prefers AuthContext (from security.auth.require_scopes) when provided,
    else falls back to request.state.user set by admin/OIDC checks, else empty.
    """
    # AuthContext path
    try:
        if auth is not None:
            sub = getattr(auth, 'subject', None) or getattr(auth, 'sub', None)
            scopes = getattr(auth, 'scopes', None)
            if sub:
                return {'sub': sub, 'scopes': scopes or []}
    except Exception:
        pass
    # request.state.user path
    try:
        if request is not None and hasattr(request, 'state') and getattr(request.state, 'user', None):
            u = getattr(request.state, 'user')
            if isinstance(u, dict):
                return u
    except Exception:
        pass
    return {}
