from datetime import datetime, timedelta

from src.core.correlation.factor_synthesis import (
    Factor,
    FactorCategory,
    FactorSynthesisEngine,
)
from src.core.correlation.factor_synthesis_runtime import factor_category_for_name


def _ts(minutes_ago: int = 0) -> datetime:
    return datetime.utcnow() - timedelta(minutes=minutes_ago)


def test_basic_combination_and_synergy():
    config = {
        "base_weights": {
            "endpoint:vss_deletion": 0.8,
            "endpoint:mass_file_rename": 0.7,
        },
        "synergy": {"endpoint:vss_deletion|endpoint:mass_file_rename": 0.2},
        "factor_fp_stats": {},
    }
    engine = FactorSynthesisEngine(config=config)
    factors = [
        Factor(name="endpoint:vss_deletion", category=FactorCategory.ENDPOINT, timestamp=_ts()),
        Factor(name="endpoint:mass_file_rename", category=FactorCategory.ENDPOINT, timestamp=_ts()),
    ]
    result = engine.synthesize(factors)
    assert result.final_score > 0.75
    assert "synergy:endpoint:vss_deletion+endpoint:mass_file_rename" in result.synergies_detected


def test_temporal_decay_and_fp_suppression():
    config = {
        "factor_fp_stats": {"endpoint:noise": {"fp_rate": 0.9}},
        "temporal": {"half_life_minutes": 10},
    }
    engine = FactorSynthesisEngine(config=config)
    factors = [
        Factor(
            name="endpoint:noise",
            category=FactorCategory.ENDPOINT,
            timestamp=_ts(minutes_ago=30),
            base_weight=0.9,
        ),
        Factor(
            name="network:beacon",
            category=FactorCategory.NETWORK,
            timestamp=_ts(minutes_ago=1),
            base_weight=0.6,
        ),
    ]
    result = engine.synthesize(factors)
    # FP suppression + decay should keep final score under purely additive values.
    assert result.final_score < 0.6
    # Explanation should note decay metadata.
    assert "Avg decay reduction" in result.explanation


def test_context_multiplier_and_confidence():
    config = {
        "context_multipliers": {"user_type:privileged": 1.2},
        "base_weights": {"identity:mfa_disabled": 0.7},
    }
    engine = FactorSynthesisEngine(config=config)
    f = Factor(
        name="identity:mfa_disabled",
        category=FactorCategory.IDENTITY,
        timestamp=_ts(),
    )
    result = engine.synthesize([f], context={"user_type": "privileged"})
    assert result.context_multiplier > 1.0
    assert result.confidence >= result.final_score


def test_full_engine_regression_components():
    config = {
        "base_weights": {
            "net:beacon_periodic": 0.65,
            "endpoint:vss_deletion": 0.7,
        },
        "context_multipliers": {
            "user_type:privileged": 1.2,
            "asset_role:tier0": 1.1,
        },
        "synergy": {
            "net:beacon_periodic|endpoint:vss_deletion": 0.25,
        },
        "factor_fp_stats": {
            "net:beacon_periodic": {"fp_rate": 0.85},
            "endpoint:vss_deletion": {"fp_rate": 0.05},
        },
        "temporal": {"half_life_minutes": 15},
    }
    engine = FactorSynthesisEngine(config=config)
    now = datetime.utcnow()
    factors = [
        Factor(
            name="net:beacon_periodic",
            category=FactorCategory.NETWORK,
            timestamp=now,
        ),
        Factor(
            name="endpoint:vss_deletion",
            category=FactorCategory.ENDPOINT,
            timestamp=now - timedelta(minutes=5),
        ),
    ]

    result = engine.synthesize(
        factors,
        context={"user_type": "privileged", "asset_role": "tier0"},
        reference_time=now,
    )

    assert result.final_score > 0.65
    assert any("synergy:" in s for s in result.synergies_detected)
    assert result.context_multiplier > 1.0
    assert result.fp_adjustment > 0.4
    names = {name: contrib for name, contrib in result.contributing_factors}
    assert names["endpoint:vss_deletion"] > names["net:beacon_periodic"]


def test_factor_category_mapping_helper():
    assert factor_category_for_name("endpoint:vss_deletion") == FactorCategory.ENDPOINT
    assert factor_category_for_name("net:beacon_periodic") == FactorCategory.NETWORK
    assert factor_category_for_name("vpn:session_hijack") == FactorCategory.REMOTE_ACCESS
    assert factor_category_for_name("unknown_factor") == FactorCategory.META
