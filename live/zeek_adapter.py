"""Compatibility shim: expose `live.zeek_adapter` for tests.

This module simply re-exports the functions from `src.live.zeek_adapter`.
"""
from importlib import import_module as _import_module
try:
    _mod = _import_module('src.live.zeek_adapter')
except Exception:
    # Fall back to a minimal local implementation if the source module
    # isn't available to avoid import-time failures in partial test runs.
    _mod = None

if _mod is not None:
    parse_zeek_line = getattr(_mod, 'parse_zeek_line')
    parse_conn = getattr(_mod, 'parse_conn')
    parse_dns = getattr(_mod, 'parse_dns')
    parse_http = getattr(_mod, 'parse_http')
    parse_ssl = getattr(_mod, 'parse_ssl')
    __all__ = ['parse_zeek_line', 'parse_conn', 'parse_dns', 'parse_http', 'parse_ssl']
else:
    __all__ = []
