"""Top-level shim package for tests that import `live.*`.

This package forwards imports to `src.live` so tests that expect
`import live` continue to work when running from the repository root.
"""
from importlib import import_module as _import_module
__all__ = []
try:
    # Expose subpackages by re-exporting the src.live package namespace
    _src_live = _import_module('src.live')
    for _name in getattr(_src_live, '__all__', []):
        try:
            globals()[_name] = getattr(_src_live, _name)
            __all__.append(_name)
        except Exception:
            pass
except Exception:
    # Best-effort fallback: leave package empty; individual submodule shims
    # will import from src.live when imported directly.
    pass
