"""
Configuration Manager - Handles configuration loading, validation, and change detection
Author: Security Engineering Team
Version: 1.0.0

Manages configuration with cryptographic hashing for provenance and change detection.
"""

import yaml
import logging
import os
from typing import Dict, Any
from pathlib import Path
from config.models import AppConfig
from pydantic import BaseModel


class ConfigNamespace(dict):
    """Dict wrapper exposing attribute-style access for config sections."""

    def __init__(self, data=None):
        super().__init__()
        if data:
            for key, value in data.items():
                super().__setitem__(key, self._wrap(value))

    def __getattr__(self, item):
        try:
            return self[item]
        except KeyError as exc:
            raise AttributeError(item) from exc

    def __setattr__(self, key, value):
        super().__setitem__(key, self._wrap(value))

    @classmethod
    def _wrap(cls, value):
        if isinstance(value, dict) and not isinstance(value, ConfigNamespace):
            return ConfigNamespace(value)
        return value

    def get(self, key, default=None):
        value = super().get(key, default)
        if isinstance(value, dict) and not isinstance(value, ConfigNamespace):
            value = ConfigNamespace(value)
            super().__setitem__(key, value)
        return value

    def setdefault(self, key, default=None):
        value = super().setdefault(key, default)
        if isinstance(value, dict) and not isinstance(value, ConfigNamespace):
            value = ConfigNamespace(value)
            super().__setitem__(key, value)
        return value


class ConfigManager:
    """Manages configuration with provenance tracking"""
    
    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self.config_data: Dict[str, Any] = {}
        self.config_digests: Dict[str, str] = {}
        self.logger = logging.getLogger(__name__)
        self.app_config: AppConfig | None = None
        
    def _wrap_value(self, value):
        """Wrap config sections to provide mapping + attribute access"""
        if isinstance(value, ConfigNamespace):
            return value
        if isinstance(value, dict):
            return ConfigNamespace(value)
        try:
            if isinstance(value, BaseModel):
                return ConfigNamespace(value.model_dump())
        except Exception:
            pass
        return value

    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file and build AppConfig"""
        raw: Dict[str, Any] = {}
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    loaded = yaml.safe_load(f) or {}
                    if not isinstance(loaded, dict):
                        raise ValueError("Config root must be a mapping")
                    raw = loaded
            self.config_data = raw
        except Exception as e:
            self.logger.error(f"Error loading config: {e}")
            self.config_data = {}

        # Build typed config
        try:
            self.app_config = AppConfig()
            self.app_config.merge_overrides(self.config_data)
            # Environment overrides (simple pattern: UPPER_DOT notation replaced by __)
            self._apply_env_overrides()
        except Exception as e:  # pragma: no cover
            self.logger.error(f"Failed constructing AppConfig: {e}")
        return self.config_data

    def _apply_env_overrides(self):
        if not self.app_config:
            return
        # DB overrides
        db_env_map = {
            'DB_HOST': ('db', 'host'),
            'DB_PORT': ('db', 'port'),
            'DB_USER': ('db', 'user'),
            'DB_PASSWORD': ('db', 'password'),
            'DB_NAME': ('db', 'database'),
        }
        for env, path in db_env_map.items():
            if env in os.environ:
                section = getattr(self.app_config, path[0])
                setattr(section, path[1], os.environ[env])
    
    def get_current_digests(self) -> Dict[str, str]:
        """Get current configuration digests"""
        return self.config_digests.copy()

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value (raw dict or typed attribute)."""
        if self.app_config and hasattr(self.app_config, key):
            value = getattr(self.app_config, key)
            return self._wrap_value(value)
        raw_value = self.config_data.get(key, default)
        wrapped = self._wrap_value(raw_value)
        if isinstance(wrapped, ConfigNamespace) and key in self.config_data:
            self.config_data[key] = wrapped
        return wrapped

    def setdefault(self, key: str, default: Any):
        """Dictionary-like helper to aid tests that expect mapping behaviour."""
        if key not in self.config_data:
            if isinstance(default, dict):
                value = dict(default)
            else:
                value = default
            self.config_data[key] = value
        else:
            value = self.config_data[key]
        if isinstance(value, dict) and self.app_config and hasattr(self.app_config, key):
            target = getattr(self.app_config, key)
            if isinstance(target, dict):
                for sub_key, sub_value in value.items():
                    target.setdefault(sub_key, sub_value)
        wrapped = self._wrap_value(value)
        if isinstance(wrapped, ConfigNamespace):
            self.config_data[key] = wrapped
        return wrapped

    # --- Mutation Helpers (for tests / dynamic toggles) ---
    def set_pipeline_flag(self, section: str, flag: str, value: Any):
        """Set a nested flag under pipeline.<section>.<flag> in raw config and apply to typed config if present.

        Creates intermediate dictionaries as needed so tests can safely toggle features without directly
        manipulating internal objects. After mutation, merges into app_config to keep runtime view consistent.
        """
        try:
            pipeline = self.config_data.setdefault('pipeline', {})
            sub = pipeline.setdefault(section, {})
            sub[flag] = value
            if self.app_config:
                # Basic merge: if app_config has 'pipeline', update nested dict if attribute exists
                if hasattr(self.app_config, 'pipeline'):
                    # assume pipeline attribute is a dict-like or object; attempt attribute then mapping
                    target = getattr(self.app_config, 'pipeline')
                    if isinstance(target, dict):
                        target.setdefault(section, {})[flag] = value
        except Exception:
            self.logger.warning("Failed to set pipeline flag", exc_info=True)
    
    def set_flag(self, dotted_path: str, value: Any) -> bool:
        """Generic nested assignment into config_data using dotted path (e.g. 'pipeline.correlation.enabled').

        Returns True if mutation succeeded. Always updates raw config; best-effort update of typed app_config.
        """
        try:
            parts = [p for p in dotted_path.split('.') if p]
            if not parts:
                return False
            cursor = self.config_data
            for p in parts[:-1]:
                nxt = cursor.get(p)
                if not isinstance(nxt, dict):
                    nxt = {}
                    cursor[p] = nxt
                cursor = nxt
            cursor[parts[-1]] = value
            # propagate to typed config if possible
            if self.app_config:
                # Walk attributes if chain exists
                obj = self.app_config
                chain_ok = True
                for p in parts[:-1]:
                    if hasattr(obj, p):
                        obj = getattr(obj, p)
                    elif isinstance(obj, dict) and p in obj:
                        obj = obj[p]
                    else:
                        chain_ok = False
                        break
                if chain_ok:
                    last = parts[-1]
                    if isinstance(obj, dict):
                        obj[last] = value
                    else:
                        if hasattr(obj, last):
                            setattr(obj, last, value)
            return True
        except Exception:
            self.logger.warning("Failed to set flag via dotted path", exc_info=True)
            return False


