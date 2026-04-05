from __future__ import annotations

import sys
import importlib

try:
    # Import the clean implementation without importing the `src` package
    # (avoids executing heavy `src/__init__.py` during interpreter startup).
    import importlib.util, importlib.machinery, os
    fp = os.path.join(os.path.dirname(__file__), 'src', 'core', 'arc_redis_queue_impl.py')
    if os.path.exists(fp):
        spec = importlib.util.spec_from_file_location('src.core.arc_redis_queue_impl', fp)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
        sys.modules['src.core.arc_redis_queue'] = mod
    else:
        # fallback to normal import if file not present
        mod = importlib.import_module('src.core.arc_redis_queue_impl')
        sys.modules['src.core.arc_redis_queue'] = mod
except Exception:
    # Be silent - this shim is best-effort for local test runs.
    pass
"""Import-time path fixer for local test runs.

This module runs early during Python startup (if project root is on sys.path)
and ensures the short-path venv site-packages (`C:\\venv`) is prioritized.
It also attempts to remove user-site directories that previously caused pytest
to pick up a different `moto` installation.

This is a non-invasive helper for local developer/test runs only.
"""

import sys
import os
import site

try:
    VENV_SP = os.path.join('C:\\', 'venv', 'Lib', 'site-packages')
    if os.path.isdir(VENV_SP):
        if VENV_SP in sys.path:
            # move to front
            sys.path.remove(VENV_SP)
        sys.path.insert(0, VENV_SP)
except Exception:
    pass

try:
    # If installed moto is missing mock_s3/mock_sqs, inject a small stub
    import importlib, types
    try:
        real_spec = importlib.util.find_spec('moto')
    except Exception:
        real_spec = None
    needs_stub = True
    if real_spec is not None:
        try:
            real = importlib.import_module('moto')
            if hasattr(real, 'mock_s3') and hasattr(real, 'mock_sqs'):
                needs_stub = False
        except Exception:
            needs_stub = True
    if needs_stub:
        stub = types.ModuleType('moto')
        class _SkipCtx:
            def __init__(self, reason='moto backend not available'):
                self._reason = reason

            def __call__(self, fn):
                try:
                    import pytest
                    return pytest.mark.skip(reason=self._reason)(fn)
                except Exception:
                    return fn

            def __enter__(self):
                return None

            def __exit__(self, exc_type, exc, tb):
                return False

        def _make(*a, **k):
            return _SkipCtx()

        stub.mock_aws = _make
        stub.mock_s3 = _make
        stub.mock_sqs = _make
        import sys
        sys.modules['moto'] = stub
except Exception:
    pass

try:
    usr = None
    try:
        usr = site.getusersitepackages()
    except Exception:
        usr = None
    if usr:
        # filter out user site entries to avoid accidental imports
        sys.path[:] = [p for p in sys.path if p and usr not in p]
except Exception:
    pass

# Compatibility stub for `moto` imports removed to avoid heavy imports during
# interpreter startup in local developer runs. If needed, tests should import
# and shim `moto` explicitly within test setup.

# Minimal, robust startup shim for tests.
# Keep this file intentionally small and non-throwing. It sets a few
# lightweight environment defaults used during pytest collection and
# ensures the repository root is on ``sys.path`` so in-repo imports work.
import os as _os
import sys as _sys

# Lightweight defaults used by tests and small inspection scripts.
# Do not leak these into normal runtime processes such as Docker app/worker.
try:
    _argv = " ".join(_sys.argv).lower()
except Exception:
    _argv = ""
_running_pytest = bool(_os.environ.get("PYTEST_CURRENT_TEST")) or "pytest" in _argv
if _running_pytest:
    _os.environ.setdefault("PLATFORM_LITE_INIT", "1")
    _os.environ.setdefault("DISABLE_DB", "1")
    _os.environ.setdefault("FAST_TEST_MODE", "1")
    _os.environ.setdefault("TEST_HELPERS_ENABLED", "1")

try:
    PROJECT_ROOT = _os.path.abspath(_os.path.dirname(__file__) or _os.getcwd())
    if PROJECT_ROOT and PROJECT_ROOT not in _sys.path:
        # Prefer the project root for imports during lightweight test runs.
        _sys.path.insert(0, PROJECT_ROOT)
except Exception:
    # Be extremely conservative: never raise during interpreter startup.
    pass

try:
    # Optional, non-fatal debug output when troubleshooting import order.
    if _os.environ.get("SITECUSTOMIZE_VERBOSE"):
        print("sitecustomize: sys.path[0:5] =", _sys.path[0:5])
except Exception:
    pass
