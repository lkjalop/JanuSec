"""Early import-time aliasing to keep short-name imports (api.*)
pointing at the canonical src.api.* modules.

This module runs on package import and ensures sys.modules entries map
api and short-name modules to the canonical src.api.* equivalents so
tests that import via api.* don't create duplicate module objects.
"""
from __future__ import annotations

import os
import sys

# Ensure top-level aliasing works regardless of import order: whether callers
# import `src.api` first or the shorter `api` path, both map to the same module
# object. Mirror common submodules as well so mixed import paths remain stable.
try:
    this_module = sys.modules.get(__name__)
    if this_module is not None:
        if __name__ == 'src.api':
            sys.modules.setdefault('api', this_module)
        elif __name__ == 'api':
            sys.modules.setdefault('src.api', this_module)
    # Map some commonly-used submodules
    common = (
        'dependencies', 'alerts_endpoints', 'analytics_endpoints', 'server',
        'state', 'routes', 'app', 'runtime_state'
    )
    for name in common:
        short = f'api.{name}'
        long = f'src.api.{name}'
        mod = sys.modules.get(long) or sys.modules.get(short)
        if mod is not None:
            sys.modules[short] = mod
            sys.modules[long] = mod
except Exception:
    # Best-effort only; failures shouldn't be fatal during import
    pass

# Lite-mode flag exposed for callers who check package state
_LITE_MODE = bool(os.environ.get('PLATFORM_LITE_INIT') or os.environ.get('SKIP_HEAVY_STARTUP'))

__all__ = ['_LITE_MODE']

try:
    import inspect
    from httpx import ASGITransport, AsyncClient
    try:
        if 'app' not in inspect.signature(AsyncClient.__init__).parameters:
            _orig_async_init = AsyncClient.__init__

            def _patched_async_init(self, *args, app=None, transport=None, **kwargs):
                if app is not None and transport is None:
                    transport = ASGITransport(app=app)
                _orig_async_init(self, *args, transport=transport, **kwargs)

            AsyncClient.__init__ = _patched_async_init  # type: ignore[attr-defined]
    except Exception:
        pass
except Exception:
    pass
