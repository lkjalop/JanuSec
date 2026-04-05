from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from src.artifact.memory_timeline import build_timeline


def test_build_timeline_linux_and_policy():
    job = SimpleNamespace(created_at=1.0)
    results = {
        "linux.pslist": [{"comm": "sshd", "pid": 22}],
        "linux.lsof": [{"process": "sshd", "fd": "3u", "path": "/usr/lib/libcrypto.so"}],
    }
    registry_entries = [{"summary": "ShimCache suspicious.exe", "source": "shimcache", "ts": 2.0}]
    entries = build_timeline(
        job,
        results,
        platform="linux",
        sandbox_policy="policy-v1",
        registry_entries=registry_entries,
    )
    kinds = {entry["kind"] for entry in entries}
    assert "process" in kinds and "file" in kinds, "linux pslist/lsof entries should be represented"
    assert any(entry["kind"] == "policy" for entry in entries), "sandbox policy entry expected"
    assert any(entry.get("source") == "shimcache" for entry in entries), "registry entries should be included"
    assert all(entry.get("platform") for entry in entries), "platform tagging required for regression packs"


def test_build_timeline_mac_fixture():
    job = SimpleNamespace(created_at=5.0)
    mac_results = json.loads(Path("tests/fixtures/memory/mac_arm_dump.json").read_text(encoding="utf-8"))
    entries = build_timeline(job, mac_results, platform="macos")
    assert any(entry.get("platform") == "macos" for entry in entries), "mac tasks should be tagged"
