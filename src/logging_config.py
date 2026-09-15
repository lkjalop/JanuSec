"""Structured JSON logging configuration.

Adds request correlation support via a context variable. Use `log_extra()` helper
to inject correlation_id and tenant_id automatically.
"""
from __future__ import annotations

import json, logging, os, sys, contextvars, datetime as _dt

correlation_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar('correlation_id', default=None)
tenant_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar('tenant_id', default=None)

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:  # noqa
        base = {
            'ts': _dt.datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'msg': record.getMessage(),
        }
        cid = correlation_id_var.get()
        if cid:
            base['correlation_id'] = cid
        tid = tenant_id_var.get()
        if tid:
            base['tenant_id'] = tid
        # Attach extras if present
        for key in ('event_id','decision_id','incident_id'):
            if hasattr(record, key):
                base[key] = getattr(record, key)
        if record.exc_info:
            base['exc_type'] = record.exc_info[0].__name__ if record.exc_info[0] else None
        return json.dumps(base, separators=(',',':'))

def configure_logging():
    if os.getenv('LOG_FORMAT','json').lower() == 'json':
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        logging.basicConfig(level=os.getenv('LOG_LEVEL','INFO').upper(), handlers=[handler])
    else:
        logging.basicConfig(level=os.getenv('LOG_LEVEL','INFO').upper())

def set_correlation(corr_id: str | None):
    correlation_id_var.set(corr_id)

def set_tenant(tenant_id: str | None):
    tenant_id_var.set(tenant_id)

def log_extra(**kw):
    # Convenience for logger.bind pattern
    return kw

__all__ = ['configure_logging','set_correlation','set_tenant','log_extra','correlation_id_var','tenant_id_var']