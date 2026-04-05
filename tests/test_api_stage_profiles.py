from __future__ import annotations

import json
from pathlib import Path

from src.core.pipeline import api_stage_profiles as profiles


def test_load_pipeline_profile_map_and_merge(tmp_path, monkeypatch):
    data = {
        "cust-a": {
            "customer_name": "Cust A",
            "pipelines": ["cust-a-prod"],
            "fixture_vectors": ["tests/data/base.json", "tests/data/a.json"],
            "notes": "demo",
        }
    }
    cfg = tmp_path / "profiles.json"
    cfg.write_text(json.dumps(data), encoding="utf-8")
    mapping = profiles.load_pipeline_profile_map(cfg)
    assert mapping["cust-a"]["customer_name"] == "Cust A"
    merged = profiles.merge_vector_paths(
        [Path("tests/data/shared.json")],
        mapping["cust-a"],
        extra=[Path("tests/data/extra.json"), Path("tests/data/a.json")],
    )
    assert [p.as_posix() for p in merged] == [
        "tests/data/shared.json",
        "tests/data/base.json",
        "tests/data/a.json",
        "tests/data/extra.json",
    ]


def test_append_manifest_entry_sorted(tmp_path, monkeypatch):
    manifest_path = tmp_path / "manifest.json"
    monkeypatch.setenv("API_STAGE_MANIFEST_PATH", str(manifest_path))
    profiles.append_manifest_entry({"ts": 1, "tenant": "a"})
    profiles.append_manifest_entry({"ts": 3, "tenant": "b"})
    profiles.append_manifest_entry({"ts": 2, "tenant": "c"})
    entries = profiles.load_manifest_entries()
    assert [entry["tenant"] for entry in entries] == ["b", "c", "a"]
