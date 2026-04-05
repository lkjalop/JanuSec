"""Configuration profile loader.

Precedence:
1. Environment variables (already set in os.environ) override everything.
2. Profile YAML values applied to os.environ for missing keys.

Usage:
    from src.config.profile_loader import apply_profile
    apply_profile('dev')

Profiles live under config/profiles/{name}.yaml.
"""
from __future__ import annotations
import os, yaml, pathlib, logging

logger = logging.getLogger('profile_loader')
_BASE = pathlib.Path('config/profiles')

def _profile_path(name: str) -> pathlib.Path:
    return _BASE / f"{name}.yaml"

def load_profile(name: str) -> dict:
    path = _profile_path(name)
    if not path.exists():
        logger.warning('profile_loader: profile %s not found (%s)', name, path)
        return {}
    try:
        with open(path,'r',encoding='utf8') as fh:
            data = yaml.safe_load(fh) or {}
        if not isinstance(data, dict):
            logger.warning('profile_loader: profile %s is not a dict', name)
            return {}
        return {str(k): str(v) for k,v in data.items()}
    except Exception as e:
        logger.error('profile_loader: failed loading profile %s: %s', name, e)
        return {}

def apply_profile(name: str) -> dict:
    """Apply a profile to the current process environment without overwriting
    existing env vars. Returns the loaded profile mapping.
    """
    prof = load_profile(name)
    for k,v in prof.items():
        if k in os.environ:
            continue  # do not override explicit environment
        os.environ[k] = v
    logger.debug('profile_loader: applied profile %s with %d keys', name, len(prof))
    return prof

__all__ = ['load_profile','apply_profile']
