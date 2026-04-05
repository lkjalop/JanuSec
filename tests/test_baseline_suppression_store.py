import json
from types import SimpleNamespace

import pytest

from src.modules.baseline import BaselineModule


@pytest.mark.asyncio
async def test_baseline_loads_suppression_state_from_file(tmp_path, monkeypatch):
    suppression_path = tmp_path / "baseline_suppressions.json"
    suppression_path.write_text(
        json.dumps(
            {
                "known_good_patterns": ["event_type:auth|src_ip:10.0.0.1"],
                "false_positive_patterns": {"event_type:auth|src_ip:10.0.0.2": 7},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("BASELINE_SUPPRESSION_PATH", str(suppression_path))
    monkeypatch.delenv("BASELINE_SKIP_WARM", raising=False)

    mod = BaselineModule(SimpleNamespace())
    await mod.initialize()

    assert "event_type:auth|src_ip:10.0.0.1" in mod.known_good_patterns
    assert mod.false_positive_patterns["event_type:auth|src_ip:10.0.0.2"] == 7


@pytest.mark.asyncio
async def test_learn_false_positive_persists_suppression_state(tmp_path, monkeypatch):
    suppression_path = tmp_path / "baseline_suppressions.json"
    monkeypatch.setenv("BASELINE_SUPPRESSION_PATH", str(suppression_path))
    monkeypatch.setenv("BASELINE_SKIP_WARM", "1")

    mod = BaselineModule(SimpleNamespace())
    await mod.learn_false_positive(
        {
            "event_type": "auth",
            "src_ip": "10.0.0.2",
            "actor": "alice@example.com",
            "action": "signin_success",
        }
    )

    stored = json.loads(suppression_path.read_text(encoding="utf-8"))
    assert stored["false_positive_patterns"]["src_ip:10.0.0.2|event_type:auth"] == 1
    assert stored["false_positive_patterns"]["identity:alice@example.com:signin_success"] == 1
