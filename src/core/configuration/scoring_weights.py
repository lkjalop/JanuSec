"""Shared helpers for scoring weight configuration used across graph sessions/UI."""
from __future__ import annotations

import json
import os
import threading
import time
from copy import deepcopy
from typing import Any, Dict

_LOCK = threading.Lock()
_CACHE: Dict[str, Any] | None = None
_CACHE_MTIME: float | None = None
_CACHE_ENV_SIG: tuple[Any, ...] | None = None

_DEFAULT_WEIGHTS = {'mapping': 0.0, 'diversity': 0.0}
_DEFAULT_ADAPTIVE = {
    'enabled': False,
    'base': 0.6,
    'min': 0.3,
    'max': 0.85,
    'scale': 0.4,
}


def _config_path() -> str:
    path = os.getenv('SCORING_WEIGHTS_PATH')
    if not path:
        path = os.path.join('data', 'scoring_weights.json')
    return path


def scoring_config_path() -> str:
    """Expose resolved path for tests."""
    return _config_path()


def _load_file() -> tuple[Dict[str, Any], float | None]:
    path = _config_path()
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            data = json.load(fh) or {}
        mtime = os.path.getmtime(path)
        return data, mtime
    except FileNotFoundError:
        return {}, None
    except Exception:
        return {}, None


def _env_signature() -> tuple[Any, ...]:
    keys = [
        'SCORING_WEIGHTS_JSON',
        'SCORING_MAPPING_WEIGHT',
        'SCORING_DIVERSITY_WEIGHT',
        'FAST_TEST_MODE',
        'ADAPTIVE_EWMA',
        'ADAPTIVE_EWMA_BASE_ALPHA',
        'ADAPTIVE_EWMA_MIN_ALPHA',
        'ADAPTIVE_EWMA_MAX_ALPHA',
        'ADAPTIVE_EWMA_VOL_SCALE',
    ]
    return tuple(os.getenv(k) for k in keys)


def _deep_copy(payload: Dict[str, Any]) -> Dict[str, Any]:
    return json.loads(json.dumps(payload))


def _normalize_weights(raw: Dict[str, Any] | None) -> Dict[str, float]:
    weights = dict(_DEFAULT_WEIGHTS)
    if not raw:
        return weights
    for key, value in raw.items():
        try:
            weights[key] = float(value)
        except Exception:
            continue
    return weights


def _normalize_adaptive(raw: Dict[str, Any] | None) -> Dict[str, Any]:
    cfg = dict(_DEFAULT_ADAPTIVE)
    if not raw:
        return cfg
    for key in ('enabled', 'base', 'min', 'max', 'scale'):
        if key not in raw:
            continue
        val = raw[key]
        if key == 'enabled':
            cfg[key] = bool(val)
        else:
            try:
                cfg[key] = float(val)
            except Exception:
                continue
    return cfg


def get_scoring_config(*, force_reload: bool = False) -> Dict[str, Any]:
    """Return merged scoring config (file + env overrides)."""
    global _CACHE, _CACHE_ENV_SIG, _CACHE_MTIME
    with _LOCK:
        env_sig = _env_signature()
        data, mtime = _load_file()
        if (
            not force_reload
            and _CACHE is not None
            and _CACHE_ENV_SIG == env_sig
            and _CACHE_MTIME == mtime
        ):
            return _deep_copy(_CACHE)

        fast_test_mode = False
        try:
            fast_test_mode = str(os.getenv('FAST_TEST_MODE', '0')).lower() in {'1', 'true', 'yes', 'on'}
        except Exception:
            fast_test_mode = False

        config: Dict[str, Any] = {
            'weights': _normalize_weights(data.get('weights')),
            'adaptive_ewma': _normalize_adaptive(data.get('adaptive_ewma')),
        }
        # In FAST_TEST_MODE, start from zeroed defaults but still honor explicit env overrides
        if fast_test_mode:
            config['weights'] = _normalize_weights({})
            weights_env = os.getenv('SCORING_WEIGHTS_JSON')
        else:
            weights_env = os.getenv('SCORING_WEIGHTS_JSON')
        if weights_env:
            try:
                parsed = json.loads(weights_env)
                config['weights'].update(_normalize_weights(parsed))
            except Exception:
                pass
        mapping_override = None if fast_test_mode else os.getenv('SCORING_MAPPING_WEIGHT')
        if mapping_override is not None:
            try:
                config['weights']['mapping'] = float(mapping_override)
            except Exception:
                pass
        diversity_override = None if fast_test_mode else os.getenv('SCORING_DIVERSITY_WEIGHT')
        if diversity_override is not None:
            try:
                config['weights']['diversity'] = float(diversity_override)
            except Exception:
                pass

        adaptive = config['adaptive_ewma']
        try:
            adaptive['enabled'] = str(os.getenv('ADAPTIVE_EWMA', '0')).lower() in {'1', 'true', 'yes', 'on'} if (weights_env is None or fast_test_mode) else adaptive['enabled']
        except Exception:
            pass
        for key, env_key in (
            ('base', 'ADAPTIVE_EWMA_BASE_ALPHA'),
            ('min', 'ADAPTIVE_EWMA_MIN_ALPHA'),
            ('max', 'ADAPTIVE_EWMA_MAX_ALPHA'),
            ('scale', 'ADAPTIVE_EWMA_VOL_SCALE'),
        ):
            val = os.getenv(env_key)
            if val is None:
                continue
            try:
                adaptive[key] = float(val)
            except Exception:
                continue

        # Keep legacy consumers in sync when no env override is present.
        # Avoid leaking overrides into environment during tests
        if not os.getenv('SCORING_WEIGHTS_JSON') and not fast_test_mode:
            try:
                os.environ['SCORING_WEIGHTS_JSON'] = json.dumps(config['weights'])
            except Exception:
                pass

        _CACHE = _deep_copy(config)
        _CACHE_ENV_SIG = env_sig
        _CACHE_MTIME = mtime
        return _deep_copy(config)


def persist_scoring_config(
    payload: Dict[str, Any],
    *,
    updated_by: str | None = None,
) -> Dict[str, Any]:
    """Persist config changes to disk and refresh cache."""
    if not isinstance(payload, dict):
        raise ValueError('payload must be a dict')
    current = get_scoring_config(force_reload=True)
    with _LOCK:
        next_config = deepcopy(current)
        record, _ = _load_file()
        record = record if isinstance(record, dict) else {}
        weights_update = payload.get('weights')
        if isinstance(weights_update, dict):
            next_config['weights'].update(_normalize_weights(weights_update))
        else:
            # Accept shorthand {"mapping":0.3,"diversity":0.05}
            for key in ('mapping', 'diversity'):
                if key in payload:
                    try:
                        next_config['weights'][key] = float(payload.get(key))
                    except Exception:
                        raise ValueError(f'invalid_{key}_weight')
        adaptive_update = payload.get('adaptive_ewma')
        if adaptive_update is not None:
            next_config['adaptive_ewma'].update(_normalize_adaptive(adaptive_update))

        prev_version = int(record.get('version', 0) or 0)
        history = record.get('history') or []
        if not isinstance(history, list):
            history = []
        if record.get('weights'):
            history.append({
                'version': prev_version,
                'weights': record.get('weights', {}),
                'adaptive_ewma': record.get('adaptive_ewma', {}),
                'updated_at': record.get('updated_at'),
                'updated_by': record.get('updated_by'),
            })
        entry = {
            'version': prev_version + 1,
            'weights': next_config['weights'],
            'adaptive_ewma': next_config['adaptive_ewma'],
            'updated_at': time.time(),
            'updated_by': updated_by or 'system',
            'history': history[-25:],
        }
        path = _config_path()
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        with open(path, 'w', encoding='utf-8') as fh:
            json.dump(entry, fh, indent=2)

        try:
            os.environ['SCORING_WEIGHTS_JSON'] = json.dumps(next_config['weights'])
        except Exception:
            pass

        # Reset cache
        global _CACHE, _CACHE_ENV_SIG, _CACHE_MTIME
        _CACHE = None
        _CACHE_ENV_SIG = None
        _CACHE_MTIME = None
        return _deep_copy(next_config)


__all__ = ['get_scoring_config', 'persist_scoring_config', 'scoring_config_path']
