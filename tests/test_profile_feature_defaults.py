from __future__ import annotations


def test_demo_profile_enables_intrusion_assessment_features(monkeypatch):
    monkeypatch.setenv("JANUSEC_PROFILE", "demo")
    monkeypatch.delenv("ENABLE_ISO_ML", raising=False)
    monkeypatch.delenv("ENABLE_EWMA_IDENTITY", raising=False)
    monkeypatch.delenv("ENABLE_IAM_FACTORS", raising=False)

    from src.core.flags import flags_snapshot

    snap = flags_snapshot()
    assert snap["JANUSEC_PROFILE"] == "demo"
    assert snap["ENABLE_ISO_ML"] is True
    assert snap["ENABLE_EWMA_IDENTITY"] is True
    assert snap["ENABLE_IAM_FACTORS"] is True


def test_prod_profile_keeps_intrusion_assessment_features_opt_in(monkeypatch):
    monkeypatch.setenv("JANUSEC_PROFILE", "prod")
    monkeypatch.delenv("ENABLE_ISO_ML", raising=False)
    monkeypatch.delenv("ENABLE_EWMA_IDENTITY", raising=False)
    monkeypatch.delenv("ENABLE_IAM_FACTORS", raising=False)

    from src.core.flags import flags_snapshot

    snap = flags_snapshot()
    assert snap["JANUSEC_PROFILE"] == "prod"
    assert snap["ENABLE_ISO_ML"] is False
    assert snap["ENABLE_EWMA_IDENTITY"] is False
    assert snap["ENABLE_IAM_FACTORS"] is False
