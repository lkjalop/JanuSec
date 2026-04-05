import json

from src.core.quality.factor_quality import FactorQualityManager


def test_quality_manager_persists_and_exports(monkeypatch, tmp_path):
    state_path = tmp_path / "factor_quality_state.json"
    monkeypatch.setenv("FACTOR_QUALITY_STATE_PATH", str(state_path))
    monkeypatch.setenv("FACTOR_MIN_OBSERVATIONS", "1")
    mgr = FactorQualityManager()
    for _ in range(3):
        mgr.record("endpoint:test_factor", is_tp=False)
    mgr.set_context_multiplier("user_role:privileged", 1.25)
    mgr.persist(force=True)

    # New manager instance should load persisted counts + context
    mgr2 = FactorQualityManager()
    stats = mgr2.export_fp_rates(min_observations=1)
    assert "endpoint:test_factor" in stats
    assert stats["endpoint:test_factor"]["fp_rate"] == 1.0
    ctx = mgr2.get_context_multipliers()
    assert ctx["user_role:privileged"] == 1.25
