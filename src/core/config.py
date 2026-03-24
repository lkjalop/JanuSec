"""Central configuration layer for platform settings.

Uses pydantic BaseSettings (v2) to validate and load environment variables.
Access via get_settings() which memoizes a singleton instance.

This begins de-risking hidden global os.getenv lookups scattered across the
codebase by providing a typed source of truth. Incrementally migrate modules
to depend on Settings rather than direct environment access.
"""
from __future__ import annotations

from functools import lru_cache
import os
try:
    # pydantic v2 moved BaseSettings to pydantic_settings
    from pydantic_settings import BaseSettings  # type: ignore
    from pydantic import Field, ValidationError, ConfigDict  # type: ignore
except Exception:  # pragma: no cover - fallback lightweight shim
    from pydantic import BaseModel, Field, ValidationError  # type: ignore
    # Provide a minimal ConfigDict shim for older pydantic versions
    class ConfigDict(dict):
        pass

    class BaseSettings(BaseModel):  # minimal fallback if pydantic_settings missing
        model_config = ConfigDict({'extra': 'ignore'})


class Settings(BaseSettings):
    model_config = ConfigDict({'extra': 'ignore'})
    api_key: str = Field(default='')
    hopgraph_snapshot_interval_seconds: int = Field(default=0)
    hopgraph_prune_interval_seconds: int = Field(default=0)
    session_ttl_seconds: int = Field(default=0)
    session_clean_interval_seconds: int = Field(default=0)
    ewma_state_path: str = Field(default='data/ewma_state.json')
    ewma_save_interval: int = Field(default=30)
    emission_coverage_threshold: int = Field(default=0)
    default_frontend: str = Field(default='console')

    def validate_intervals(self) -> None:
        for name in (
            'hopgraph_snapshot_interval_seconds',
            'hopgraph_prune_interval_seconds',
            'session_ttl_seconds',
            'session_clean_interval_seconds',
            'ewma_save_interval',
        ):
            v = getattr(self, name)
            if v < 0:
                raise ValueError(f"{name} must be >= 0 (got {v})")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    try:
        # Construct Settings without per-field env mapping; read environment
        # variables here to avoid using deprecated Field(env=...).
        env = {
            'api_key': os.getenv('API_KEY', ''),
            'hopgraph_snapshot_interval_seconds': int(os.getenv('HOPGRAPH_SNAPSHOT_INTERVAL_SECONDS', '0') or 0),
            'hopgraph_prune_interval_seconds': int(os.getenv('HOPGRAPH_PRUNE_INTERVAL_SECONDS', '0') or 0),
            'session_ttl_seconds': int(os.getenv('SESSION_TTL_SECONDS', '0') or 0),
            'session_clean_interval_seconds': int(os.getenv('SESSION_CLEAN_INTERVAL_SECONDS', '0') or 0),
            'ewma_state_path': os.getenv('DATA_EWMA_STATE_PATH', 'data/ewma_state.json'),
            'ewma_save_interval': int(os.getenv('DATA_EWMA_SAVE_INTERVAL', '30') or 30),
            'emission_coverage_threshold': int(os.getenv('EMISSION_COVERAGE_THRESHOLD', '0') or 0),
            'default_frontend': os.getenv('DEFAULT_FRONTEND', 'console'),
        }
        s = Settings(**env)  # type: ignore[arg-type]
        s.validate_intervals()
        return s
    except ValidationError as ve:  # pragma: no cover - early startup fatal
        # Re-raise with simpler message
        raise RuntimeError(f"Configuration validation failed: {ve}") from ve

__all__ = ['Settings', 'get_settings']
