from __future__ import annotations
from typing import Callable
import inspect
from functools import update_wrapper

def preserve_signature(wrapper: Callable, original: Callable) -> None:
    """Ensure the wrapper exposes the original function's signature.

    This sets ``__wrapped__`` and ``__signature__`` so frameworks like FastAPI
    that introspect call signatures see the real parameters instead of a
    generic ``*args, **kwargs`` signature which can create spurious query
    parameters (e.g., 'kwargs'). Call this immediately when returning the
    wrapper from a decorator factory so the correct signature is present at
    route-registration time.
    """
    try:
        # update_wrapper sets __wrapped__ and common dunder attrs
        update_wrapper(wrapper, original)
    except Exception:
        try:
            # Best-effort fallback
            wrapper.__wrapped__ = original
        except Exception:
            pass
    # Attach the original signature (best-effort)
    try:
        wrapper.__signature__ = inspect.signature(original)
    except Exception:
        # If signature can't be obtained, leave as-is; frameworks will fall back
        # but this should be rare for well-defined functions.
        pass
