import os

from src.core.quality.factor_quality import FactorQualityManager


def test_factor_quality_history_fallback(monkeypatch, tmp_path):
    state_path = tmp_path / "fq_state.json"
    monkeypatch.setenv("FACTOR_QUALITY_STATE_PATH", str(state_path))
    monkeypatch.setenv("FACTOR_MIN_OBSERVATIONS", "10")
    monkeypatch.setenv("FACTOR_HISTORY_HALF_LIFE_MINUTES", "5")
    manager = FactorQualityManager()
    manager.record("endpoint:test_factor", True)
    manager.record("endpoint:test_factor", False)
    rates = manager.export_fp_rates()
    assert "endpoint:test_factor" in rates
    history = rates["endpoint:test_factor"].get("history")
    assert history and history["fp"] > 0
    snapshot = manager.history_snapshot()
    assert any(row["factor"] == "endpoint:test_factor" for row in snapshot)
