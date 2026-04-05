"""Centralized configuration for HopGraph / API settings.

Provides a typed layer over environment variables to reduce sprawl and
offer discoverability. Only a subset of currently used vars are modeled; new
ones can be added incrementally.
"""
from __future__ import annotations
from pydantic import BaseSettings, Field, field_validator
from functools import lru_cache
from typing import Optional


class Settings(BaseSettings):
    # HopGraph explain / stitching
    stitch_depth: int = Field(2, env='HOPGRAPH_STITCH_DEPTH')
    stitch_beam: int = Field(3, env='HOPGRAPH_STITCH_BEAM')
    gt_sequence_weight: float = Field(3.2, env='HOPGRAPH_GT_SEQUENCE_WEIGHT')
    forced_edge_cap: float = Field(4.0, env='HOPGRAPH_FORCED_EDGE_CAP')
    adaptive_stitch_threshold: float = Field(0.0, env='HOPGRAPH_ADAPTIVE_STITCH_THRESHOLD')
    adaptive_stitch_increment: int = Field(2, env='HOPGRAPH_ADAPTIVE_STITCH_INCREMENT')
    bridging_enabled: bool = Field(False, env='HOPGRAPH_BRIDGING_ENABLED')
    bridging_seq_threshold: float = Field(0.25, env='HOPGRAPH_BRIDGING_SEQ_THRESHOLD')
    bridging_max_hops: int = Field(3, env='HOPGRAPH_BRIDGING_MAX_HOPS')

    # SLO thresholds (used by regression test)
    min_recall: float = Field(0.35, env='HOPGRAPH_MIN_RECALL')
    min_sequence_score: float = Field(0.24, env='HOPGRAPH_MIN_SEQUENCE_SCORE')

    # RBAC / auth (future expansion)
    rbac_enabled: bool = Field(False, env='HOPGRAPH_RBAC_ENABLED')

    class Config:
        case_sensitive = False
        env_file = '.env'
        env_file_encoding = 'utf-8'

    @field_validator('stitch_depth','stitch_beam','adaptive_stitch_increment','bridging_max_hops',mode='after')
    def _positive(cls, v):  # noqa: D401
        if v < 0:
            raise ValueError('value must be non-negative')
        return v


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()

__all__ = ['Settings','get_settings']
