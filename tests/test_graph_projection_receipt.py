import datetime as dt

from src.core.evidence_contract.graph_projection import GraphProjectionReceipt, StalenessReason, projection_staleness


def _receipt(**overrides):
    values = dict(
        tenant_id="tenant-a", case_id="case-1", projection_id="projection-1",
        ledger_head_hash="a" * 64, node_ids=("n2", "n1"), edge_ids=("e1",),
        normalizer_version="norm-1", mapping_version="map-1", built_at="2026-08-18T00:00:00Z",
        source_watermarks={"aws": "2026-08-18T00:00:00Z"}, topology_valid_to="2026-08-19T00:00:00Z",
    )
    values.update(overrides)
    return GraphProjectionReceipt(**values)


def test_projection_receipt_is_content_addressed_and_order_stable():
    first = _receipt()
    second = _receipt(node_ids=("n1", "n2"))
    assert first.receipt_id == second.receipt_id
    assert first.to_dict()["record_type"] == "graph_view_receipt"


def test_projection_staleness_names_the_reason_without_mutating_history():
    reasons = projection_staleness(
        _receipt(), current_ledger_head_hash="b" * 64, normalizer_version="norm-2", mapping_version="map-1",
        now=dt.datetime(2026, 8, 20, tzinfo=dt.timezone.utc), sensor_max_age_seconds={"aws": 3600},
        clock_calibration_hash="new-clock-hash",
        iam_receipt_hash="new-iam", topology_receipt_hash="new-topology",
        cmdb_receipt_hash="new-cmdb",
    )
    assert StalenessReason.LEDGER_ADVANCED in reasons
    assert StalenessReason.NORMALIZER_CHANGED in reasons
    assert StalenessReason.TOPOLOGY_EXPIRED in reasons
    assert StalenessReason.SENSOR_WATERMARK_EXPIRED in reasons
    assert StalenessReason.CLOCK_CALIBRATION_CHANGED in reasons
    assert StalenessReason.IAM_CHANGED in reasons
    assert StalenessReason.TOPOLOGY_CHANGED in reasons
    assert StalenessReason.CMDB_CHANGED in reasons
