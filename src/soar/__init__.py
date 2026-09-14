"""Simple SOAR playbook runner package (MVP).

This module contains a lightweight in-process playbook runner used for demos.
Playbooks are JSON/YAML with a list of steps. Runner runs steps sequentially and
supports dry-run mode by default.
"""

from __future__ import annotations

__all__ = ["runner"]

import importlib
import pkgutil
from collections.abc import Awaitable, Callable
from typing import Any, Dict

_ACTIONS: dict[str, BaseAction] = {}

class BaseAction:
    name: str = 'base'
    description: str = ''
    timeout_seconds: float = 10.0

    async def run(self, context: dict[str, Any]) -> dict[str, Any]:  # pragma: no cover - interface
        raise NotImplementedError

def register(action: BaseAction) -> None:
    _ACTIONS[action.name] = action

def get(name: str) -> BaseAction:
    return _ACTIONS[name]

def list_actions() -> list[str]:
    return sorted(_ACTIONS.keys())

__all__ = ['BaseAction','register','get','list_actions']

def discover_actions(package: str = 'src.soar.actions') -> None:
    """Dynamically import all modules in the actions package so they register themselves.

    This avoids relying on implicit package-level imports. Idempotent.
    """
    for _finder, name, _ispkg in pkgutil.iter_modules(importlib.import_module(package).__path__):
        full = f"{package}.{name}"
        try:
            importlib.import_module(full)
        except Exception:
            # defensive: don't fail startup because one action failed to import
            continue


# Backwards-compatible: import common bundled actions as a fallback
try:
    from .actions import (
        slack_notify,  # pragma: no cover - registration
        tag_event,
    )
except Exception:  # pragma: no cover - defensive
    pass

__all__ = ['BaseAction','register','get','list_actions','discover_actions']
