"""Plugin registry loader.

Reads a JSON registry describing SOAR actions & factor extractors and attempts
best-effort dynamic imports. Failures are logged but non-fatal.
"""
from __future__ import annotations

import json
import logging
import os
import importlib
from typing import Any, Dict

logger = logging.getLogger(__name__)

REGISTRY_PATH = os.getenv('PLUGIN_REGISTRY_PATH','plugins/registry.json')

_loaded: dict[str, Any] = {
    'soar_actions': {},
    'factor_extractors': {},
    'version': None,
}

def load_registry() -> dict[str, Any]:
    if not os.path.exists(REGISTRY_PATH):
        logger.info('Plugin registry file not found: %s', REGISTRY_PATH)
        return _loaded
    try:
        with open(REGISTRY_PATH, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
        _loaded['version'] = data.get('version')
        for group in ('soar_actions','factor_extractors'):
            entries = data.get(group) or []
            for entry in entries:
                if not entry.get('enabled', True):
                    continue
                mod_path = entry.get('module')
                name = entry.get('name')
                if not (mod_path and name):
                    continue
                try:
                    module = importlib.import_module(mod_path)
                    _loaded[group][name] = module
                except Exception as exc:  # pragma: no cover
                    logger.debug('Failed loading plugin %s (%s): %s', name, mod_path, exc)
    except Exception as exc:  # pragma: no cover
        logger.warning('Plugin registry load failed: %s', exc)
    return _loaded

def get_loaded_plugins() -> dict[str, Any]:  # simple accessor
    return _loaded

__all__ = ['load_registry','get_loaded_plugins']
