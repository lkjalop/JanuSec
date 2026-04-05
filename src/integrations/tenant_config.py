from __future__ import annotations

"""Tenant configuration helpers for email detectors and collectors.

Sources:
- Environment variables (simple CSVs / scalars)
- Optional JSON file path via EMAIL_CONFIG_PATH

Shape:
{
  "vip_names": ["ceo","cfo",...],
  "corporate_domains": ["example.com","corp.example.com"],
  "thresholds": {"bec": 0.6},
  "poll": {"gmail": 300, "o365": 300}
}
"""

import json
import os
import threading
from typing import Dict, Any, List

_lock = threading.Lock()
_cache: Dict[str, Any] | None = None
_cache_mtime: float | None = None


def _csv_env(name: str) -> List[str]:
    v = os.getenv(name)
    if not v:
        return []
    return [p.strip() for p in v.split(',') if p.strip()]


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default


def _load_file(path: str) -> Dict[str, Any]:
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            return json.load(fh)
    except Exception:
        return {}


def load_email_config() -> Dict[str, Any]:
    global _cache, _cache_mtime
    path = os.getenv('EMAIL_CONFIG_PATH')
    if path:
        try:
            mtime = os.path.getmtime(path)
        except Exception:
            mtime = None
    else:
        mtime = None

    with _lock:
        if _cache is not None and (_cache_mtime == mtime):
            return _cache

        data: Dict[str, Any] = {}
        file_data: Dict[str, Any] = _load_file(path) if path else {}
        data.update(file_data if isinstance(file_data, dict) else {})

        vip = data.get('vip_names') or _csv_env('EMAIL_VIP_NAMES')
        corp = data.get('corporate_domains') or _csv_env('EMAIL_CORPORATE_DOMAINS')
        thresholds = data.get('thresholds') or {}
        poll = data.get('poll') or {}
        # env overrides
        poll_gmail = _int_env('GMAIL_POLL_INTERVAL', poll.get('gmail', 300))
        poll_o365 = _int_env('O365_POLL_INTERVAL', poll.get('o365', 300))
        data = {
            'vip_names': vip or [
                'ceo','chief executive officer','cto','cfo','coo','chief technology officer','john smith','jane doe'
            ],
            'corporate_domains': corp or ['example.com','corp.example.com'],
            'thresholds': thresholds,
            'poll': {'gmail': poll_gmail, 'o365': poll_o365},
        }
        _cache = data
        _cache_mtime = mtime
        return data


__all__ = ['load_email_config']
