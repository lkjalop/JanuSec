import json

from src.core import risk_score


class _DummyQuality:
    def export_fp_rates(self, min_observations=None):
        return {"endpoint:noise": {"fp_rate": 0.95}}

    def get_context_multipliers(self):
        return {"user_role:privileged": 1.1}


def test_risk_score_uses_factor_synthesis(monkeypatch, tmp_path):
    cfg_path = tmp_path / "factor_synth.json"
    cfg_path.write_text(json.dumps({"base_weights": {"endpoint:noise": 0.9}}), encoding="utf-8")
    monkeypatch.setenv("FACTOR_SYNTHESIS_CONFIG", str(cfg_path))
    monkeypatch.setenv("FAST_TEST_MODE", "1")
    monkeypatch.setattr(risk_score, "_FACTOR_SYNTHESIS_ENGINE", None)
    monkeypatch.setattr(risk_score, "_FACTOR_SYNTHESIS_SIGNATURE", None)
    monkeypatch.setattr(risk_score, "_FACTOR_SYNTHESIS_BASE_CACHE", None)
    monkeypatch.setattr(risk_score, "_FACTOR_SYNTHESIS_BASE_PATH", None)
    monkeypatch.setattr(risk_score, "_FACTOR_SYNTHESIS_BASE_MTIME", None)
    monkeypatch.setattr(risk_score, "get_quality_manager", lambda: _DummyQuality())

    decision = {"factors": ["endpoint:noise"], "confidence": 1.0, "role": "privileged"}
    result = risk_score.compose_risk_score(decision)
    synthesis_entries = [b for b in result["breakdown"] if b["factor"] == "factor_synthesis"]
    assert synthesis_entries, "factor synthesis breakdown entry missing"
    meta = synthesis_entries[0].get("metadata") or {}
    assert meta.get("context_multiplier", 0) > 1.0
    insights = decision.get("correlation_insights") or []
    assert any(i.get("type") == "factor_synthesis" for i in insights)


class _FixtureQuality:
    def export_fp_rates(self, min_observations=None):
        return {}

    def get_context_multipliers(self):
        return {"severity:critical": 1.15}


def test_factor_synthesis_synergy_fixture(monkeypatch, tmp_path):
    cfg_path = tmp_path / "factor_synth_fixture.json"
    cfg = {
        "base_weights": {
            "endpoint:vss_deletion": 0.7,
            "endpoint:mass_file_rename": 0.65,
        },
        "synergy": {
            "endpoint:vss_deletion|endpoint:mass_file_rename": 0.25,
        },
        "factor_history": [
            {"factor": "endpoint:vss_deletion", "tp": 25, "fp": 2},
            {"factor": "endpoint:mass_file_rename", "tp": 22, "fp": 1},
        ],
    }
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
    monkeypatch.setenv("FACTOR_SYNTHESIS_CONFIG", str(cfg_path))
    monkeypatch.setenv("FAST_TEST_MODE", "1")
    monkeypatch.setattr(risk_score, "_FACTOR_SYNTHESIS_ENGINE", None)
    monkeypatch.setattr(risk_score, "_FACTOR_SYNTHESIS_SIGNATURE", None)
    monkeypatch.setattr(risk_score, "_FACTOR_SYNTHESIS_BASE_CACHE", None)
    monkeypatch.setattr(risk_score, "_FACTOR_SYNTHESIS_BASE_PATH", None)
    monkeypatch.setattr(risk_score, "_FACTOR_SYNTHESIS_BASE_MTIME", None)
    monkeypatch.setattr(risk_score, "get_quality_manager", lambda: _FixtureQuality())

    decision = {
        "factors": ["endpoint:vss_deletion", "endpoint:mass_file_rename"],
        "confidence": 0.82,
        "severity": "critical",
    }
    result = risk_score.compose_risk_score(decision)
    synth_entry = next(b for b in result["breakdown"] if b["factor"] == "factor_synthesis")
    meta = synth_entry["metadata"]
    assert meta["synergies"], "expected synergy list from fixture"
    assert synth_entry["contribution"] >= 0.9
    assert decision["correlation_insights"], "decision should carry factor_synthesis insight"
