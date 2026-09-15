"""Adapters package registry.

Provides a simple registry for connectors so ingestion pipeline can obtain
instances by name.
"""
from typing import Dict, Any

_REGISTRY: Dict[str, Any] = {}


def register(name: str, obj: Any):
    _REGISTRY[name] = obj


def get(name: str):
    return _REGISTRY.get(name)


def list_registered():
    return list(_REGISTRY.keys())


# Attempt to auto-register known connectors gracefully
try:
    from .qualys_connector import QualysConnector  # type: ignore
    register('qualys', QualysConnector)
except Exception:
    # Fail silently when connector can't be imported in test-lite environments
    pass

