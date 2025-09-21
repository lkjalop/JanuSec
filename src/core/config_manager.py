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


class ConfigManager:
    """Manages configuration with provenance tracking"""
    
    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self.config_data: Dict[str, Any] = {}
        self.config_digests: Dict[str, str] = {}
        self.logger = logging.getLogger(__name__)
        self.app_config: AppConfig | None = None
        
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
            return getattr(self.app_config, key)
        return self.config_data.get(key, default)