"""Adapters and helpers to make heavy stage runners callable from worker processes.

This module provides utilities to expose a stable module+function entrypoint
for heavy stages that may be wrapped or declared as class methods. Use the
`adapter_for(module_path, attr_name)` to create small module-level wrapper
functions that forward to the underlying callable while remaining picklable.
"""
from __future__ import annotations

from types import ModuleType, SimpleNamespace
import importlib
import functools
from typing import Any, Callable


def _unwrap_callable(obj: Any) -> Any:
    """Attempt to find underlying wrapped function via __wrapped__ chain."""
    seen = set()
    cur = obj
    while True:
        if id(cur) in seen:
            break
        seen.add(id(cur))
        wrapped = getattr(cur, '__wrapped__', None)
        if wrapped is None:
            break
        cur = wrapped
    return cur


def resolve_runner(module_path: str, attr_name: str) -> Callable:
    """Import module and resolve the call target (function or class runner).

    Returns a callable that accepts (event, ctx) and returns a StageResult-like
    object or awaitable. The returned callable is the unwrapped underlying
    callable where possible.
    """
    mod = importlib.import_module(module_path)
    if not hasattr(mod, attr_name):
        raise AttributeError(f'{attr_name} not found in {module_path}')
    target = getattr(mod, attr_name)
    unwrapped = _unwrap_callable(target)
    return unwrapped


def adapter_for(module_path: str, attr_name: str):
    """Return a module-level adapter function that can be placed in a module
    so `execute_stage_runner` can import it by name.

    Example:
      # in src/core/event_pipeline/stages/heavy_stage.py
      from src.core.event_pipeline.process_adapter import adapter_for
      run_heavy = adapter_for(__name__, 'real_heavy_runner')

    The returned `run_heavy` is a plain function that will call
    `real_heavy_runner(event, ctx)` (awaiting if needed).
    """
    def _adapter(event, ctx):
        runner = resolve_runner(module_path, attr_name)
        # Call synchronously if possible, otherwise create and return coroutine
        res = runner(event, ctx)
        return res

    # Annotate hints for debugging
    _adapter.__name__ = f'adapter_{attr_name}'
    _adapter.__module__ = module_path
    return _adapter
