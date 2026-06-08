from __future__ import annotations

from src.core.calibration.confidence_calibration import (
    apply_calibration,
    calibration_metrics,
    fit_artifact,
    samples_from_assessment,
)


def test_confidence_calibration_exports_metrics_and_applies_platt():
    assessment = {
        "assessment_id": "assessment-vesper-test",
        "org": "vesper",
        "clusters": [
            {
                "cluster_id": "c1",
                "final_verdict": "VALIDATED_BREACH",
                "confidence": 0.9,
                "source_count": 3,
                "factor_tags": ["iam:golden_ticket", "network:c2"],
            },
            {
                "cluster_id": "c2",
                "final_verdict": "BENIGN_EXPECTED",
                "confidence": 0.2,
                "source_count": 1,
                "factor_tags": ["noise:admin"],
            },
        ],
    }

    samples = samples_from_assessment(assessment)
    assert samples == [
        {
            "assessment_id": "assessment-vesper-test",
            "cluster_id": "c1",
            "raw_confidence": 0.9,
            "final_verdict": "VALIDATED_BREACH",
            "ground_truth_label": 1,
            "dataset": "vesper",
            "source_count": 3,
            "factor_count": 2,
        },
        {
            "assessment_id": "assessment-vesper-test",
            "cluster_id": "c2",
            "raw_confidence": 0.2,
            "final_verdict": "BENIGN_EXPECTED",
            "ground_truth_label": 0,
            "dataset": "vesper",
            "source_count": 1,
            "factor_count": 1,
        },
    ]

    metrics = calibration_metrics(samples, bins=5)
    assert metrics["count"] == 2
    assert metrics["brier"] is not None
    assert metrics["ece"] is not None
    assert len(metrics["bins"]) == 5

    artifact = fit_artifact(samples, method="platt")
    applied = apply_calibration(0.9, dataset="vesper", artifact=artifact)
    assert applied["applied"] is True
    assert applied["method"] == "platt"
    assert 0.0 <= applied["probability"] <= 1.0
