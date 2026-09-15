"""
Compatibility shim package so imports like `import api.server` resolve to
the real source files under `src/api/` without duplicating module namespaces.

This keeps tests that use both `api.*` and `src.api.*` working in a single
process pytest run by pointing the package search path to `src/api`.
"""
import os
import sys
import importlib

# Make package loader search the real `src/api` directory for submodules.
_here = os.path.dirname(__file__)
_src_api = os.path.abspath(os.path.join(_here, '..', 'src', 'api'))
__path__ = [_src_api]

# Ensure module aliases point to the canonical src.api package so that
# api.* and src.api.* share the same module objects.
try:
    src_pkg = importlib.import_module('src.api')
    sys.modules.setdefault('src.api', src_pkg)
    sys.modules.setdefault('api', src_pkg)
    # Mirror commonly used submodules to avoid duplicate imports.
    for name in (
        'dependencies', 'alerts_endpoints', 'analytics_endpoints', 'server',
        'state', 'routes', 'app', 'runtime_state'
    ):
        short = f'api.{name}'
        long = f'src.api.{name}'
        mod = sys.modules.get(long) or sys.modules.get(short)
        if mod is not None:
            sys.modules[short] = mod
            sys.modules[long] = mod
except Exception:
    # Best-effort aliasing; fall back to path shim if import fails.
    pass
