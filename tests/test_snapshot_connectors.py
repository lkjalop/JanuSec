import datetime as dt

from src.core.evidence_contract.signed_snapshots import verify_snapshot
from src.core.evidence_contract.snapshot_connectors import SignedSnapshotConnector, collect_sandbox_infrastructure_truth


def test_connector_collects_and_signs_versioned_provider_snapshot():
    connector = SignedSnapshotConnector(
        kind="iam", source="aws-organizations+iam/v1",
        fetcher=lambda: {"authorization_paths": [{"principal": "p1", "resource": "s3://b"}]},
    )
    snapshot = connector.collect(
        tenant_id="tenant-a", version="etag-42", valid_from="2026-08-20T00:00:00Z", key="secret",
    )
    assert snapshot["snapshot_receipt"]["version"] == "etag-42"
    assert verify_snapshot(snapshot, expected_kind="iam", tenant_id="tenant-a", key="secret") == (True, "verified")


def test_connector_rejects_empty_or_unknown_snapshots():
    try:
        SignedSnapshotConnector(kind="cti", source="x", fetcher=lambda: {"x": 1}).collect(
            tenant_id="t", version="1", valid_from="2026-08-20T00:00:00Z", key="k",
        )
        raise AssertionError("unknown kind accepted")
    except ValueError as exc:
        assert str(exc) == "unsupported_snapshot_kind"
    try:
        SignedSnapshotConnector(kind="cmdb", source="x", fetcher=lambda: {}).collect(
            tenant_id="t", version="1", valid_from="2026-08-20T00:00:00Z", key="k",
        )
        raise AssertionError("empty snapshot accepted")
    except ValueError as exc:
        assert str(exc) == "empty_snapshot_rejected"


def test_sandbox_collectors_sign_explicit_iam_topology_and_cmdb_truth():
    bundle = collect_sandbox_infrastructure_truth(
        tenant_id="tenant-a", version="sandbox-7",
        valid_from="2026-08-20T00:00:00Z", valid_to="2026-08-21T00:00:00Z",
        key="acceptance-secret", key_id="sandbox-key-1",
        iam={"authorization_paths": [{"principal": "user:james", "resource": "role:prod-reader"}]},
        topology={
            "allowed_routes": [{"source": "host:ws-james", "target": "host:bastion"}],
            "denied_routes": [["host:guest", "host:bastion"]],
        },
        cmdb={"asset_service_mappings": [{
            "asset_id": "host:bastion", "service_id": "svc:payments",
            "service": {"id": "svc:payments", "name": "Payments", "criticality": "high"},
        }]},
    )
    assert bundle["iam"]["allowed_paths"] == [["user:james", "role:prod-reader"]]
    assert bundle["topology"]["allowed_routes"] == [["host:ws-james", "host:bastion"]]
    assert bundle["cmdb"]["asset_service_mappings"] == [["host:bastion", "svc:payments"]]
    assert bundle["cmdb"]["mapped_services_hash"]
    for kind, snapshot in bundle.items():
        assert verify_snapshot(
            snapshot, expected_kind=kind, tenant_id="tenant-a", key="acceptance-secret",
            as_of=dt.datetime(2026, 8, 20, 12, tzinfo=dt.timezone.utc),
        ) == (True, "verified")


def test_sandbox_cmdb_rejects_implicit_business_impact_without_asset_mapping():
    connector = SignedSnapshotConnector(
        kind="cmdb", source="sandbox/cmdb/v1",
        fetcher=lambda: {"business_services": [{"id": "svc:payments", "name": "Payments"}]},
    )
    try:
        connector.collect(
            tenant_id="tenant-a", version="1", valid_from="2026-08-20T00:00:00Z",
            valid_to="2026-08-21T00:00:00Z", key="secret",
        )
        raise AssertionError("implicit CMDB impact mapping accepted")
    except ValueError as exc:
        assert str(exc) == "cmdb_snapshot_requires_explicit_asset_service_mappings"


def test_data_classification_and_regulatory_applicability_require_explicit_scope():
    classification = SignedSnapshotConnector(
        kind="data_classification", source="catalog/v1",
        fetcher=lambda: {"asset_classifications": [{
            "asset_id": "db:customer", "classification": "restricted",
            "data_categories": ["personal_data"],
        }]},
    ).collect(tenant_id="tenant-a", version="7", valid_from="2026-08-22T00:00:00Z", key="k")
    assert classification["classification_mapping_hash"]
    applicability = SignedSnapshotConnector(
        kind="regulatory_applicability", source="grc-profile/v1",
        fetcher=lambda: {"obligations": [{
            "obligation_id": "privacy-review-au", "authority": "approved legal profile",
            "jurisdiction": "AU", "version": "2026-08", "applicability_status": "review_required",
            "applicable_to": {"data_categories": ["personal_data"]},
        }]},
    ).collect(tenant_id="tenant-a", version="8", valid_from="2026-08-22T00:00:00Z", key="k")
    assert applicability["applicability_mapping_hash"]
