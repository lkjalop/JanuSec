"""Structured Config Models using Pydantic"""
from __future__ import annotations
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, AnyUrl

class DBConfig(BaseModel):
    dsn: Optional[str] = Field(default=None, description="Full DSN override")
    host: str = "localhost"
    port: int = 5432
    user: str = "postgres"
    password: str = "postgres"
    database: str = "janusec"  # renamed default (legacy: threatsifter)
    min_size: int = 1
    max_size: int = 10

class PipelineBlendingConfig(BaseModel):
    mode: str = Field(default="add", pattern="^(add|max|weighted_max)$")
    baseline_weight: float = 1.0
    regex_weight: float = 1.0
    cap: float = 1.0

class PipelineConfig(BaseModel):
    blending: PipelineBlendingConfig = PipelineBlendingConfig()
    disable_adaptive_pre: bool = False

class SlackChannelMapping(BaseModel):
    low: Optional[str] = None
    medium: Optional[str] = None
    high: Optional[str] = None
    critical: Optional[str] = None

class SlackConfig(BaseModel):
    enabled: bool = False
    webhook_url: Optional[str] = None
    default_channel: Optional[str] = None
    channel_map: SlackChannelMapping = SlackChannelMapping()
    rate_limit_per_minute: int = 30

class ConfidenceThresholds(BaseModel):
    benign_threshold: float = 0.1
    malicious_threshold: float = 0.9

class AppConfig(BaseModel):
    db: DBConfig = DBConfig()
    pipeline: PipelineConfig = PipelineConfig()
    slack: SlackConfig = SlackConfig()
    confidence: ConfidenceThresholds = ConfidenceThresholds()

    class Config:
        arbitrary_types_allowed = True

    def merge_overrides(self, overrides: Dict[str, Any]):
        """Shallow merge overrides (dict style) into this model"""
        for k, v in overrides.items():
            if hasattr(self, k):
                current = getattr(self, k)
                if isinstance(v, dict) and isinstance(current, BaseModel):
                    # Nested update
                    data = current.model_dump()
                    data.update(v)
                    updated = current.__class__(**data)
                    setattr(self, k, updated)
                else:
                    setattr(self, k, v)
        return self
