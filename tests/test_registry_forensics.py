from __future__ import annotations

import json
from pathlib import Path

from src.artifact.registry_forensics import RegistryForensics


def test_registry_forensics_parses_userassist(tmp_path):
    rf = RegistryForensics(evidence_path=tmp_path / "registry.jsonl")
    results = {
        "windows.registry.shimcache": [{"path": "C:\\temp\\evil.exe", "timestamp": 1700000000, "Signed": False}],
        "windows.registry.amcache": [{"path": "C:\\temp\\tool.exe", "timestamp": 1700000100, "hash": "abc"}],
        "windows.registry.userassist": [{"Program": "powershell.exe", "Count": 88, "LastRun": 1700000200}],
        "windows.registry.mru": [{"path": "C:\\payload.docm", "timestamp": 1700000300}],
        "windows.registry.browser_history": [{"url": "https://portal-login.example", "timestamp": 1700000400}],
    }
    damaged = json.loads(Path("tests/fixtures/registry_damaged.json").read_text(encoding="utf-8"))
    results["windows.registry.shimcache"].extend(damaged)
    summary = rf.analyze(results, {"host": "HOST", "case_id": "CASE"})
    assert summary["userassist"], "userassist entries should be mapped"
    assert summary["mru"], "mru entries should be present"
    assert summary["browser"], "browser history should be present"
    assert "registry:userassist_spike" in summary["factors"], "spike factor expected"
