from src.core.evidence_contract.snapshot_connectors import SignedSnapshotConnector
from src.core.grc.obligation_engine import evaluate_obligations


def _snapshots():
    classification = SignedSnapshotConnector(
        kind="data_classification", source="catalog",
        fetcher=lambda: {"asset_classifications": [{
            "asset_id": "db:customer", "classification": "restricted", "data_categories": ["personal_data"],
        }]},
    ).collect(tenant_id="t", version="1", valid_from="2026-08-22T00:00:00Z", key="k")
    applicability = SignedSnapshotConnector(
        kind="regulatory_applicability", source="approved-profile",
        fetcher=lambda: {"obligations": [{
            "obligation_id": "privacy-review", "authority": "approved counsel profile",
            "jurisdiction": "AU", "version": "2026-08", "applicability_status": "applicable",
            "applicable_to": {"data_categories": ["personal_data"]},
            "trigger_conditions": {"unauthorized_access_confirmed": True},
            "notification_window": "as defined in source reference", "source_reference": "policy://privacy/2026-08",
        }]},
    ).collect(tenant_id="t", version="1", valid_from="2026-08-22T00:00:00Z", key="k")
    return classification, applicability


def test_obligation_requires_human_review_without_trigger_facts(monkeypatch):
    monkeypatch.setenv("JANUSEC_SNAPSHOT_HMAC_KEY", "k")
    classification, applicability = _snapshots()
    result = evaluate_obligations(
        tenant_id="t", affected_asset_ids=["db:customer"], affected_service_ids=[],
        data_classification_snapshot=classification, regulatory_applicability_snapshot=applicability,
    )
    assert result["decision_status"] == "legal_or_privacy_review_required"
    assert result["obligations"][0]["notification_window"] == "as defined in source reference"


def test_obligation_likely_triggered_needs_explicit_fact_and_evidence(monkeypatch):
    monkeypatch.setenv("JANUSEC_SNAPSHOT_HMAC_KEY", "k")
    classification, applicability = _snapshots()
    result = evaluate_obligations(
        tenant_id="t", affected_asset_ids=["db:customer"], affected_service_ids=[],
        data_classification_snapshot=classification, regulatory_applicability_snapshot=applicability,
        incident_facts={"unauthorized_access_confirmed": True, "evidence_ids": ["ev-1"]},
    )
    assert result["decision_status"] == "obligation_likely_triggered"
    assert result["obligations"][0]["supporting_evidence_ids"] == ["ev-1"]


def test_obligation_engine_abstains_without_signed_truth():
    result = evaluate_obligations(
        tenant_id="t", affected_asset_ids=[], affected_service_ids=[],
        data_classification_snapshot=None, regulatory_applicability_snapshot=None,
    )
    assert result["decision_status"] == "insufficient_information"
    assert len(result["gaps"]) == 2
