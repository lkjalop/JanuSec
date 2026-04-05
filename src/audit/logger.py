"""Structured audit logger.

Writes JSON lines to data/audit.log (append). Best-effort; failures are silent.
Used for:
 - Forced edge injections
 - gt_sequence edge insertions
 - Bridging expansions
"""
from __future__ import annotations
import json, time, logging
from pathlib import Path
from typing import Any, Dict
import os

LOGGER = logging.getLogger('audit')

# Default on-disk path; tests can override by setting AUDIT_PATH env var
AUDIT_PATH = Path('data/audit.log')
AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)

def audit(event: str, **fields: Any) -> None:
    """Write a compact JSON line to the audit file and emit a structured log.

    This function is best-effort and will swallow IO errors to avoid breaking
    request paths that call it.
    """
    rec: Dict[str, Any] = {'ts': time.time(), 'event': event}
    rec.update(fields)
    s = None
    try:
        s = json.dumps(rec, separators=(',', ':'))
    except Exception:
        try:
            # fallback: stringify minimally
            s = json.dumps({'ts': rec.get('ts'), 'event': str(event)})
        except Exception:
            s = None
    # append to file (best-effort)
    try:
        if s is not None:
            with AUDIT_PATH.open('a', encoding='utf-8') as f:
                f.write(s + '\n')
    except Exception:
        pass
    # also emit structured log for collectors that scrape logs
    try:
        # Use logger.info with the JSON string as message. Downstream log shippers
        # or formatters can parse this. Avoid raising on failure.
        if s is not None:
            LOGGER.info(s)
    except Exception:
        pass

__all__ = ['audit']

def audit_event(payload: Dict[str, Any]) -> None:
    try:
        audit(payload.get('event') or 'event', **{k: v for k, v in payload.items() if k != 'event'})
    except Exception:
        pass

def enable_json_logging_if_requested():
    try:
        if os.getenv('ENABLE_JSON_LOG', '0').lower() in {'1','true','yes'}:
            import logging, sys
            handler = logging.StreamHandler(sys.stdout)
            fmt = '%(message)s'
            handler.setFormatter(logging.Formatter(fmt))
            LOGGER.addHandler(handler)
            LOGGER.setLevel(logging.INFO)
    except Exception:
        pass

enable_json_logging_if_requested()
