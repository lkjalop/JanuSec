"""Registry for generated module-level adapters for heavy/wrapped stages.

Adapters are small functions created at runtime that import and call the
underlying stage runner by module+name. This helps `execute_stage_runner`
locate and call a stage in a worker process even when the original runner
is a wrapped function or a bound method.
"""
from __future__ import annotations

import importlib
from types import ModuleType
from typing import Callable, Dict
from .process_adapter import resolve_runner


_ADAPTERS: Dict[str, Callable] = {}


def make_adapter_name(stage_name: str) -> str:
    return f'__adapter_{stage_name}'


def register_adapter(stage_name: str, module_path: str, attr_name: str) -> str:
    """Create and register an adapter for the given stage. Returns the
    module-qualified name that can be imported by the worker (module_path, adapter_name).
    """
    adapter_name = make_adapter_name(stage_name)
    key = f'{module_path}.{attr_name}->{adapter_name}'
    if key in _ADAPTERS:
        return f'{module_path}.{adapter_name}'

    # Create a simple adapter that calls the resolved runner
    def adapter(event, ctx):
        runner = resolve_runner(module_path, attr_name)
        return runner(event, ctx)

    adapter.__name__ = adapter_name
    adapter.__module__ = module_path
    _ADAPTERS[key] = adapter
    return f'{module_path}.{adapter_name}'


def get_registered_adapters() -> Dict[str, Callable]:
    return dict(_ADAPTERS)
