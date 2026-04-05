"""Top-level `azure` shim.

This shim is intentionally small: it defers to any installed `azure`
distribution for normal imports (e.g., `azure.functions`) and exposes a
convenience `repo` attribute that points at `azure_repo` (the repository's
copy of legacy azure function helpers) so internal code can access the
repo-local modules without shadowing installed packages.
"""
from __future__ import annotations

import importlib
import types

__all__ = ["functions", "repo"]

# Try to import the real azure package (installed in site-packages).
try:
    real_azure = importlib.import_module('azure')
    # If the real package is found and it's not this module, re-export its
    # `functions` attribute if present for normal usage.
    functions = getattr(real_azure, 'functions', None)
except Exception:
    # Fallback: there may be no installed azure; expose minimal placeholders.
    functions = None

# Import the repository-local copy under `azure_repo` and expose it via
# the `repo` attribute so internal code can do `azure.repo.functions...`.
try:
    repo = importlib.import_module('azure_repo')
except Exception:
    repo = types.SimpleNamespace()

