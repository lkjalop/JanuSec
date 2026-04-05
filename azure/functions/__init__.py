"""azure.functions compatibility shim.

Prefer the installed `azure.functions` package when available. When the
installed package is absent, fall back to the repository-local copy that
was moved into `azure_repo.functions`.
"""
from __future__ import annotations

import importlib
import types

try:
    # Prefer real installed azure.functions
    _real_af = importlib.import_module('azure.functions')
    EventHubEvent = getattr(_real_af, 'EventHubEvent', None)
    EventGridEvent = getattr(_real_af, 'EventGridEvent', None)
    HttpRequest = getattr(_real_af, 'HttpRequest', None)
    HttpResponse = getattr(_real_af, 'HttpResponse', None)
    # Expose the defender_eventhub submodule if present upstream
    try:
        defender_eventhub = importlib.import_module('azure.functions.defender_eventhub')
    except Exception:
        defender_eventhub = None
except Exception:
    # Fallback: import from repository copy under azure_repo
    try:
        _repo_funcs = importlib.import_module('azure_repo.functions')
        defender_eventhub = getattr(_repo_funcs, 'defender_eventhub', None)
    except Exception:
        defender_eventhub = None

__all__ = [name for name in ('EventHubEvent', 'EventGridEvent', 'HttpRequest', 'HttpResponse', 'defender_eventhub') if globals().get(name) is not None]
