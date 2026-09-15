"""Lightweight feature flag registry.

Environment-driven; parse FEATURE_FLAGS on each call so tests that modify
the environment can pick up changes without relying on module reloads.
Flags may be comma- or space-separated in the FEATURE_FLAGS env var.
"""
from __future__ import annotations
import os
from typing import Set, List


def _parse_flags(raw: str | None) -> Set[str]:
    raw = (raw or '').strip()
    if not raw:
        return set()
    parts: list[str] = []
    # Normalize commas and spaces
    raw_norm = raw.replace(',', ' ')
    parts = [p.strip().lower() for p in raw_norm.split() if p.strip()]
    return set(parts)


def is_enabled(name: str) -> bool:
    flags = _parse_flags(os.getenv('FEATURE_FLAGS', ''))
    return name.lower() in flags


def all_flags() -> List[str]:
    return sorted(list(_parse_flags(os.getenv('FEATURE_FLAGS', ''))))


__all__ = ['is_enabled', 'all_flags']