"""Shared helpers for API stage tenant/pipeline fixtures and manifest tracking."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List
import json
import os

PIPELINE_CONFIG_ENV = "API_STAGE_PIPELINE_CONFIG"
MANIFEST_PATH_ENV = "API_STAGE_MANIFEST_PATH"
DEFAULT_PIPELINE_CONFIG = Path("config/api_stage_pipeline_profiles.json")
DEFAULT_MANIFEST_PATH = Path("logs/perf/api_stage/manifest.json")


def _coerce_path(value: str | Path) -> Path:
    if isinstance(value, Path):
        return value
    return Path(str(value))


def _pipeline_config_path(path: str | Path | None = None) -> Path:
    if path:
        return _coerce_path(path)
    env_override = os.getenv(PIPELINE_CONFIG_ENV)
    if env_override:
        return _coerce_path(env_override)
    return DEFAULT_PIPELINE_CONFIG


def _manifest_path(path: str | Path | None = None) -> Path:
    if path:
        p = _coerce_path(path)
    else:
        env_override = os.getenv(MANIFEST_PATH_ENV)
        p = _coerce_path(env_override) if env_override else DEFAULT_MANIFEST_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def load_pipeline_profile_map(path: str | Path | None = None) -> dict[str, dict[str, Any]]:
    """Load the tenant -> pipeline metadata map."""
    cfg_path = _pipeline_config_path(path)
    if not cfg_path.exists():
        return {}
    try:
        data = json.loads(cfg_path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    profiles: dict[str, dict[str, Any]] = {}
    for raw_name, raw_meta in data.items():
        if not isinstance(raw_meta, dict):
            continue
        name = str(raw_name)
        meta = dict(raw_meta)
        fixture_vectors = meta.get("fixture_vectors") or meta.get("vector_overrides") or []
        if isinstance(fixture_vectors, str):
            fixture_vectors = [fixture_vectors]
        meta["fixture_vectors"] = [
            str(_coerce_path(entry))
            for entry in fixture_vectors
            if entry
        ]
        meta["pipelines"] = [str(p) for p in meta.get("pipelines") or []]
        meta["customer_name"] = meta.get("customer_name") or name
        meta["notes"] = meta.get("notes")
        if meta.get("artifact_base_url"):
            meta["artifact_base_url"] = str(meta["artifact_base_url"])
        profiles[name] = meta
    return profiles


def merge_vector_paths(
    base: Iterable[str | Path],
    pipeline_meta: dict[str, Any] | None = None,
    extra: Iterable[str | Path] | None = None,
) -> list[Path]:
    """Combine shared + tenant-specific fixture packs without duplicates."""
    combined: list[Path] = []
    seen: set[str] = set()

    def _add(path_value: str | Path | None):
        if not path_value:
            return
        p = _coerce_path(path_value)
        key = str(p)
        if key in seen:
            return
        seen.add(key)
        combined.append(p)

    for entry in base:
        _add(entry)
    if pipeline_meta:
        for entry in pipeline_meta.get("fixture_vectors") or []:
            _add(entry)
    if extra:
        for entry in extra:
            _add(entry)
    return combined


def load_manifest_entries(path: str | Path | None = None) -> list[dict[str, Any]]:
    """Return manifest entries sorted newest -> oldest."""
    manifest_file = _manifest_path(path)
    if not manifest_file.exists():
        return []
    try:
        data = json.loads(manifest_file.read_text(encoding="utf-8"))
    except Exception:
        return []
    if isinstance(data, dict) and "entries" in data:
        entries = data["entries"]
    elif isinstance(data, list):
        entries = data
    else:
        entries = []
    sanitized: list[dict[str, Any]] = []
    for entry in entries:
        if isinstance(entry, dict):
            sanitized.append(entry)
    sanitized.sort(key=lambda e: e.get("ts") or 0, reverse=True)
    return sanitized


def write_manifest(entries: list[dict[str, Any]], path: str | Path | None = None) -> Path:
    manifest_file = _manifest_path(path)
    payload = {"entries": entries}
    manifest_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return manifest_file


def append_manifest_entry(entry: dict[str, Any], path: str | Path | None = None, *, max_entries: int = 60) -> Path:
    """Append a new artifact entry while capping history length."""
    entries = load_manifest_entries(path)
    entries.append(entry)
    entries.sort(key=lambda e: e.get("ts") or 0, reverse=True)
    if max_entries and len(entries) > max_entries:
        entries = entries[:max_entries]
    return write_manifest(entries, path)


__all__ = [
    "DEFAULT_MANIFEST_PATH",
    "DEFAULT_PIPELINE_CONFIG",
    "append_manifest_entry",
    "load_manifest_entries",
    "load_pipeline_profile_map",
    "merge_vector_paths",
]
