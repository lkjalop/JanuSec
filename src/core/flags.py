"""Feature flags registry and helpers.

Centralize change-safety and canary toggles. Flags are sourced from env vars
and can be overridden at runtime via a lightweight in-memory overlay that can
optionally be persisted to ``config/flags.json`` for durability across restarts.

Intended use:
- Read flags using ``get_flag(name, default)`` only (do not read env directly).
- Admin endpoints may call ``set_flag``/``clear_flag`` to flip values at runtime.
- ``flags_snapshot`` returns the effective view (env + overrides applied).
"""
from __future__ import annotations

import os
from typing import Any, Dict
import json
from pathlib import Path


def _b(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).lower() in {"1","true","yes"}


def _f(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except Exception:
        return default


def _i(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default


def _profile() -> str:
    return str(os.getenv('JANUSEC_PROFILE') or os.getenv('APP_ENV') or os.getenv('ENV') or 'prod').strip().lower()


def _default_enabled_for(*profiles: str) -> bool:
    return _profile() in {p.lower() for p in profiles}


_overrides: Dict[str, Any] = {}


def _load_overrides() -> None:
    """Best-effort load overrides from config/flags.json or FLAGS_FILE path."""
    global _overrides
    try:
        p = Path(os.getenv('FLAGS_FILE', 'config/flags.json'))
        if p.exists():
            data = json.loads(p.read_text(encoding='utf-8'))
            if isinstance(data, dict):
                # normalize boolean-like strings into proper types if present
                cleaned: Dict[str, Any] = {}
                for k, v in data.items():
                    if isinstance(v, str) and v.lower() in {"true","false","1","0","yes","no"}:
                        cleaned[k] = v.lower() in {"true","1","yes"}
                    else:
                        cleaned[k] = v
                _overrides = cleaned
    except Exception:
        # keep overrides empty on failure
        pass


def _save_overrides() -> None:
    """Persist overrides to config/flags.json (best-effort)."""
    try:
        p = Path(os.getenv('FLAGS_FILE', 'config/flags.json'))
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(_overrides, indent=2, sort_keys=True), encoding='utf-8')
    except Exception:
        # swallow persistence errors (admin API will still return new state)
        pass


def flags_snapshot() -> Dict[str, Any]:
    profile = _profile()
    demo_default = _default_enabled_for('demo', 'dev', 'local')
    base = {
        'JANUSEC_PROFILE': profile,
        # SLO display/enforcement
        'FEATURE_SLO_ENFORCE_DISPLAY': _b('FEATURE_SLO_ENFORCE_DISPLAY', False),
        'SLO_EWMA_ALPHA': _f('SLO_EWMA_ALPHA', 0.3),
        # RL canary controls
        'RL_CANARY_ENABLED': _b('RL_CANARY_ENABLED', False),
        'RL_CANARY_CAPACITY': _i('RL_CANARY_CAPACITY', int(os.getenv('RL_DEFAULT_CAPACITY', '10'))),
        'RL_CANARY_REFILL': _f('RL_CANARY_REFILL', float(os.getenv('RL_DEFAULT_REFILL', '5.0'))),
        # Circuit breakers
        'CB_ENABLED': _b('CB_ENABLED', False),
        'CB_SLACK_ENABLED': _b('CB_SLACK_ENABLED', _b('CB_ENABLED', False)),
        'CB_ECLIPSE_ENABLED': _b('CB_ECLIPSE_ENABLED', _b('CB_ENABLED', False)),
        'CB_FAIL_THRESHOLD': _i('CB_FAIL_THRESHOLD', 3),
        'CB_RESET_SECONDS': _f('CB_RESET_SECONDS', 30.0),
        'CB_HALF_OPEN_TRIALS': _i('CB_HALF_OPEN_TRIALS', 1),
        # Outbox
        'OUTBOX_ENABLED': _b('OUTBOX_ENABLED', False),
        'OUTBOX_BACKEND': os.getenv('OUTBOX_BACKEND', ''),
        # Identity/ML/Privacy feature toggles
        'ENABLE_ISO_ML': _b('ENABLE_ISO_ML', demo_default),
        'ENABLE_LS_TEMPORAL': _b('ENABLE_LS_TEMPORAL', False),
        'ENABLE_EWMA_IDENTITY': _b('ENABLE_EWMA_IDENTITY', demo_default),
        'ENABLE_IAM_FACTORS': _b('ENABLE_IAM_FACTORS', demo_default),
        'PRIVACY_DEFAULT_MODE': os.getenv('PRIVACY_DEFAULT_MODE', ''),
    }
    # Apply overrides last (runtime wins)
    try:
        eff = dict(base)
        eff.update(_overrides)
        return eff
    except Exception:
        return base


def get_flag(name: str, default: Any = None) -> Any:
    snap = flags_snapshot()
    return snap.get(name, default)


def set_flag(name: str, value: Any, persist: bool = True) -> None:
    """Override a flag at runtime. Optionally persist to flags.json."""
    _overrides[name] = value
    if persist:
        _save_overrides()


def clear_flag(name: str, persist: bool = True) -> None:
    """Remove a runtime override, revealing env/default value."""
    if name in _overrides:
        _overrides.pop(name, None)
        if persist:
            _save_overrides()


def list_overrides() -> Dict[str, Any]:
    """Return current override dict (copy)."""
    return dict(_overrides)


# Load overrides at import time (best-effort)
_load_overrides()
