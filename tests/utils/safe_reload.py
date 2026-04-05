"""Test helper: safe_reload and alias normalization helpers.

This module provides a safe_reload(module_or_name) helper that ensures
canonical sys.modules aliases for common package name differences (e.g.
"src.api.app" <-> "api.app") before delegating to importlib.reload.

It is small and testable so conftest can import and reuse it instead of
embedding ad-hoc logic.
"""
from __future__ import annotations
import importlib
import sys
from types import ModuleType
from typing import Optional


def _canonical_aliases_for(name: str) -> list[str]:
    """Return a list of likely alias module names for `name`.

    For names like 'src.api.server' return ['api.server','src.api.server'] so
    callers can ensure both entries point to the same module object.
    """
    out = [name]
    try:
        if name.startswith('src.'):
            short = name[len('src.'):]
            out.append(short)
        elif name.startswith('api.'):
            out.append('src.' + name)
    except Exception:
        pass
    return out


def normalize_aliases_for_module(module: ModuleType) -> None:
    """Ensure sys.modules contains canonical aliases for the given module.

    This will set common short/long aliases to point to the same module
    object so importlib.reload and monkeypatch operations target a
    single canonical object.
    """
    try:
        name = getattr(module, '__spec__', None) and getattr(module.__spec__, 'name', None) or getattr(module, '__name__', None)
        if not name:
            return
        for alias in _canonical_aliases_for(name):
            if sys.modules.get(alias) is not module:
                sys.modules[alias] = module
    except Exception:
        pass


def safe_reload(module_or_name: ModuleType | str) -> Optional[ModuleType]:
    """Reload a module safely, ensuring canonical sys.modules aliases exist.

    Accepts either a module object or a module name. If a name is provided,
    importlib.import_module(...) will be used to obtain the module object.
    Returns the reloaded module or None on failure.
    """
    try:
        if isinstance(module_or_name, str):
            module = importlib.import_module(module_or_name)
        else:
            module = module_or_name
        # Ensure aliases are normalized first so reload operates on the
        # canonical sys.modules entries and tests that patch alternate names
        # observe the same object.
        try:
            normalize_aliases_for_module(module)
        except Exception:
            pass
        try:
            return importlib.reload(module)
        except Exception:
            # If reload fails, attempt a best-effort re-execution of the
            # module source into the existing module object so module-level
            # globals are reinitialized (tests often rely on reload to pick
            # up environment changes). This is a guarded fallback and may
            # still fail for some import styles, in which case return the
            # original module instance.
            try:
                spec = getattr(module, '__spec__', None)
                origin = getattr(spec, 'origin', None) if spec is not None else None
                if origin and isinstance(origin, str) and os.path.exists(origin):
                    with open(origin, 'r', encoding='utf-8') as fh:
                        src = fh.read()
                    code = compile(src, origin, 'exec')
                    # Prepare a fresh namespace preserving import-time attrs
                    new_ns = {'__name__': module.__name__, '__spec__': module.__spec__}
                    try:
                        exec(code, new_ns)
                        # Replace module dict contents while preserving object identity
                        module.__dict__.clear()
                        module.__dict__.update(new_ns)
                        return module
                    except Exception:
                        # Fall-through to return original module
                        return module
            except Exception:
                return module
    except Exception:
        try:
            # Fallback to calling reload on what importlib provides for the name
            if isinstance(module_or_name, str):
                m = importlib.import_module(module_or_name)
                return importlib.reload(m)
        except Exception:
            pass
    # As a last resort, if we could resolve a module object return it; otherwise None
    try:
        return module  # type: ignore[name-defined]
    except Exception:
        return None
