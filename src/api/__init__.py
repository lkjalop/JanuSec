"""Early import-time aliasing to keep short-name imports (api.*)
pointing at the canonical src.api.* modules.

This module runs on package import and ensures sys.modules entries map
api and short-name modules to the canonical src.api.* equivalents so
tests that import via api.* don't create duplicate module objects.
"""
from __future__ import annotations

import os
import sys
import importlib
import importlib.abc
import importlib.machinery


# --- Canonical-alias finder ------------------------------------------------
# Without this, importing `api.X` and `src.api.X` produces two distinct module
# objects even though they back the same source file (because the `api`
# package's `__path__` points at `src/api/` but Python registers loaded modules
# under whichever fullname was requested). The duplicates break test
# monkeypatching: patches land on one copy while the running code uses the
# other. This finder makes both names always resolve to the same module.
class _AliasLoader(importlib.abc.Loader):
    """Loader that replaces a freshly-created shell module with an existing
    canonical module, so `api.X` ends up as the SAME object as `src.api.X`.

    Implementation detail: returning `self._module` from `create_module()`
    is unreliable — CPython's `_load_unlocked()` does `setattr(parent, child,
    module)` after `exec_module()`, using whatever `module_from_spec()`
    returned. If a freshly-shell module is created and we don't replace
    `sys.modules[spec.name]` during exec_module, the parent package ends up
    holding the shell, while `sys.modules[spec.name]` holds the canonical —
    producing the dual-module bug.

    By overwriting `sys.modules[spec.name]` inside `exec_module`, CPython's
    pop/re-add dance at the tail of `_load_unlocked()` returns the canonical
    module and the parent attribute is set correctly.
    """

    def __init__(self, module):
        self._module = module

    def create_module(self, spec):
        # Return None so Python creates a fresh shell; we substitute it below.
        if os.environ.get('JANUSEC_API_ALIAS_DEBUG'):
            print(f"[alias-loader.create_module] spec.name={spec.name} canon id={id(self._module)}")
        return None

    def exec_module(self, _shell):
        import sys as _s
        target_name = getattr(self._module, '__name__', None)
        shell_name = getattr(_shell, '__name__', None)
        if os.environ.get('JANUSEC_API_ALIAS_DEBUG'):
            print(f"[alias-loader.exec_module] shell={shell_name} id={id(_shell)} canon={target_name} id={id(self._module)} sys[shell]={id(_s.modules.get(shell_name))}")
        for key in (target_name, shell_name):
            if key:
                _s.modules[key] = self._module
        if os.environ.get('JANUSEC_API_ALIAS_DEBUG'):
            print(f"[alias-loader.exec_module] after replace sys[{shell_name}]={id(_s.modules.get(shell_name))} sys[{target_name}]={id(_s.modules.get(target_name))}")
        return None


class _CanonicalApiAliasFinder(importlib.abc.MetaPathFinder):
    """Map any import of `api.X` to the canonical `src.api.X` module.

    IMPORTANT: this finder must NOT pre-set `sys.modules[fullname]` before
    returning a spec. CPython's `_find_spec` contains this short-circuit::

        if name in sys.modules:
            return module.__spec__

    If `sys.modules[name]` is already populated, Python discards our spec
    and uses the existing module's own `__spec__` (whose loader is the
    canonical SourceFileLoader) — which causes the source file to be
    re-executed under the canonical name and replaces the canonical module
    with a fresh duplicate. The alias never takes effect.

    Instead we return a spec backed by `_AliasLoader`, which during
    `exec_module()` swaps the freshly created shell module out of
    `sys.modules` and replaces it with the canonical module. CPython's
    `_load_unlocked` then pops the replacement and assigns it as the parent
    package attribute, giving us a single shared module under both names.
    """

    _ALIAS_PREFIX = 'api.'
    _CANONICAL_PREFIX = 'src.api.'

    def find_spec(self, fullname, path, target=None):
        try:
            if not fullname.startswith(self._ALIAS_PREFIX):
                return None
            if fullname.startswith(self._CANONICAL_PREFIX):
                return None
            sub = fullname[len(self._ALIAS_PREFIX):]
            if not sub:
                return None
            canonical = self._CANONICAL_PREFIX + sub
            existing = sys.modules.get(canonical)
            if existing is None:
                try:
                    existing = importlib.import_module(canonical)
                except Exception:
                    return None
            spec = importlib.machinery.ModuleSpec(fullname, loader=_AliasLoader(existing))
            spec.has_location = False
            return spec
        except Exception:
            return None


if not any(isinstance(_f, _CanonicalApiAliasFinder) for _f in sys.meta_path):
    sys.meta_path.insert(0, _CanonicalApiAliasFinder())


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
