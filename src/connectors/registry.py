"""Connector registry: load policies, enable/disable, and resolve connectors.

Policies are stored in JSON at data/connectors_policies.json for simplicity.
Each connector may define: enabled, quotas, cost_cap_usd, rate_limit, allow_hosts.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, Optional

from src.connectors.sdk import BaseConnector
from src.core.rate_limit import TokenBucketLimiter

logger = logging.getLogger(__name__)


def _record_failure(code: str, msg: str, exc: Exception | None = None) -> None:
    """Make a swallowed registry failure observable (warning + metric) instead of a
    silent `pass`/`return {}`. Control flow is unchanged — the registry still degrades
    gracefully — but a corrupt policy file or failed save is no longer invisible."""
    logger.warning("connector registry: %s — %s%s", code, msg, f": {exc}" if exc else "")
    try:
        from src.core.metrics.connectors_metrics import ingest_errors_total
        ingest_errors_total.labels("registry", code).inc()
    except Exception:
        pass


_POLICY_PATH = os.environ.get('CONNECTORS_POLICY_PATH', os.path.join('data', 'connectors_policies.json'))
_REGISTRY: Dict[str, BaseConnector] = {}
_POLICIES: Dict[str, Dict[str, Any]] = {}
_CONFIGS: Dict[str, Dict[str, Any]] = {}
_CONFIG_PATH = os.environ.get('CONNECTORS_CONFIG_PATH', os.path.join('data', 'connectors_configs.json'))


def _policy_path() -> str:
    return os.environ.get('CONNECTORS_POLICY_PATH', os.path.join('data', 'connectors_policies.json'))


def _config_path() -> str:
    return os.environ.get('CONNECTORS_CONFIG_PATH', os.path.join('data', 'connectors_configs.json'))


def _ensure_dirs() -> None:
    try:
        os.makedirs(os.path.dirname(_policy_path()) or 'data', exist_ok=True)
    except Exception:
        pass


def load_policies() -> Dict[str, Dict[str, Any]]:
    _ensure_dirs()
    path = _policy_path()
    if not os.path.exists(path):
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            return json.load(fh)
    except Exception as exc:
        # A corrupt policy file silently disabling every connector's policy is exactly
        # the kind of invisible outage this makes observable.
        _record_failure("policy_load", f"could not read {path}", exc)
        return {}


def save_policies(policies: Dict[str, Dict[str, Any]]) -> None:
    _ensure_dirs()
    try:
        with open(_policy_path(), 'w', encoding='utf-8') as fh:
            json.dump(policies, fh, indent=2)
    except Exception as exc:
        _record_failure("policy_save", f"could not write {_policy_path()}", exc)


def load_configs() -> Dict[str, Dict[str, Any]]:
    _ensure_dirs()
    path = _config_path()
    if not os.path.exists(path):
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            return json.load(fh)
    except Exception as exc:
        _record_failure("config_load", f"could not read {path}", exc)
        return {}


def save_configs(configs: Dict[str, Dict[str, Any]]) -> None:
    _ensure_dirs()
    try:
        with open(_config_path(), 'w', encoding='utf-8') as fh:
            json.dump(configs, fh, indent=2)
    except Exception as exc:
        _record_failure("config_save", f"could not write {_config_path()}", exc)


def register(name: str, connector: BaseConnector) -> None:
    _REGISTRY[name] = connector


def apply_policy(name: str, policy: Dict[str, Any]) -> None:
    """Apply a policy to an existing connector instance if present."""
    conn = _REGISTRY.get(name)
    if not conn:
        return
    try:
        rate_cfg = policy.get('rate_limit', {}) or {}
        rps = float(rate_cfg.get('rate_per_second', 0) or 0)
        burst = float(rate_cfg.get('burst', 0) or 0)
        if rps > 0 and hasattr(conn, 'rate_limiter'):
            try:
                from src.core.rate_limit import TokenBucketLimiter
                conn.rate_limiter = TokenBucketLimiter(rps, burst or max(rps, 1.0))
            except Exception:
                pass
        if hasattr(conn, 'allow_hosts'):
            try:
                conn.allow_hosts = set(policy.get('allow_hosts') or [])
            except Exception as exc:
                _record_failure("apply_allow_hosts", f"{name}", exc)
    except Exception as exc:
        _record_failure("apply_policy", f"{name}", exc)


def get(name: str) -> Optional[BaseConnector]:
    return _REGISTRY.get(name)


def get_policy(name: str) -> Dict[str, Any]:
    global _POLICIES
    if not _POLICIES:
        _POLICIES = load_policies()
    return _POLICIES.get(name, {})


def ensure_connector(name: str, factory) -> BaseConnector:
    conn = get(name)
    if conn:
        return conn
    pol = get_policy(name)
    rate_cfg = pol.get('rate_limit', {'rate_per_second': 5.0, 'burst': 10.0})
    limiter = TokenBucketLimiter(rate_cfg.get('rate_per_second', 5.0), rate_cfg.get('burst', 10.0))
    allow_hosts = set(pol.get('allow_hosts') or [])
    conn = factory(rate_limiter=limiter, allow_hosts=allow_hosts)
    register(name, conn)
    # apply any saved config
    try:
        cfg = get_config(name)
        if cfg and hasattr(conn, 'set_config'):
            try:
                conn.set_config(cfg)
            except Exception as exc:
                _record_failure("ensure_set_config", f"{name}", exc)
    except Exception as exc:
        _record_failure("ensure_connector", f"{name}", exc)
    return conn


def is_enabled(name: str) -> bool:
    pol = get_policy(name)
    return bool(pol.get('enabled', True))


def set_policy(name: str, policy: Dict[str, Any]) -> None:
    global _POLICIES
    if not _POLICIES:
        _POLICIES = load_policies()
    _POLICIES[name] = policy
    save_policies(_POLICIES)
    # apply to live connector instances
    try:
        apply_policy(name, policy)
    except Exception as exc:
        _record_failure("set_policy_apply", f"{name}", exc)


def get_config(name: str) -> Dict[str, Any]:
    global _CONFIGS
    if not _CONFIGS:
        _CONFIGS = load_configs()
    return _CONFIGS.get(name, {})


def set_config(name: str, cfg: Dict[str, Any]) -> None:
    global _CONFIGS
    if not _CONFIGS:
        _CONFIGS = load_configs()
    _CONFIGS[name] = cfg
    save_configs(_CONFIGS)
    # notify live connector
    try:
        conn = _REGISTRY.get(name)
        if conn and hasattr(conn, 'set_config'):
            try:
                conn.set_config(cfg)
            except Exception as exc:
                _record_failure("set_config_notify", f"{name}", exc)
    except Exception as exc:
        _record_failure("set_config", f"{name}", exc)


# Attempt to load builtin connector registration modules (email connectors, etc.)
try:
    import sys
    from src.connectors import email_connectors as _ec
    try:
        if hasattr(_ec, 'register'):
            # pass this registry module object which exposes `register()`
            _ec.register(sys.modules[__name__])
    except Exception as exc:
        _record_failure("builtin_register", "email_connectors", exc)
except Exception:
    # email_connectors module absent is an expected optional-dependency case, not a
    # failure worth alerting on.
    pass
