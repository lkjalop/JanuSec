from __future__ import annotations

import os
import json
import threading
from typing import Optional, Dict

_lock = threading.Lock()
_store_path = os.getenv('CONNECTOR_CREDENTIALS_PATH', 'data/connector_credentials.json')


def _load_store() -> Dict[str, dict]:
    try:
        if os.path.exists(_store_path):
            with open(_store_path, 'r', encoding='utf-8') as fh:
                return json.load(fh)
    except Exception:
        pass
    return {}


def _save_store(data: Dict[str, dict]):
    try:
        os.makedirs(os.path.dirname(_store_path) or 'data', exist_ok=True)
        with open(_store_path, 'w', encoding='utf-8') as fh:
            json.dump(data, fh)
    except Exception:
        pass


def get_credentials(connector_name: str, tenant: Optional[str] = None) -> Optional[dict]:
    key = f"{tenant or 'default'}::{connector_name}"
    with _lock:
        store = _load_store()
        return store.get(key)


def set_credentials(connector_name: str, creds: dict, tenant: Optional[str] = None) -> None:
    key = f"{tenant or 'default'}::{connector_name}"
    with _lock:
        store = _load_store()
        store[key] = creds
        _save_store(store)


def delete_credentials(connector_name: str, tenant: Optional[str] = None) -> None:
    key = f"{tenant or 'default'}::{connector_name}"
    with _lock:
        store = _load_store()
        if key in store:
            del store[key]
            _save_store(store)


__all__ = ['get_credentials', 'set_credentials', 'delete_credentials']
