"""Simple helpers for persisting LLM provider settings.

This module uses a single JSON file path configurable via the
`LLM_SETTINGS_PATH` environment variable. It intentionally tolerates
missing or corrupt files and returns an empty dict in those cases.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

LLM_SETTINGS_PATH = Path(os.getenv("LLM_SETTINGS_PATH", "config/llm_settings.json"))


def load_settings() -> Dict[str, Any]:
    try:
        if not LLM_SETTINGS_PATH.exists():
            return {}
        with LLM_SETTINGS_PATH.open("r", encoding="utf-8") as fp:
            data = json.load(fp)
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def save_settings(payload: Dict[str, Any]) -> None:
    LLM_SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LLM_SETTINGS_PATH.open("w", encoding="utf-8") as fp:
        json.dump(payload, fp, indent=2)
