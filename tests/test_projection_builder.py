from src.core.evidence_contract.projection_builder import build_typed_projection, evidence_id_for_row


def test_projection_builder_separates_candidate_exposure_and_causality():
    rows = [
        {"row_index": 1, "source_type": "sysmon", "EventID": 1, "Image": "powershell.exe", "ParentImage": "cmd.exe", "user": "alex", "src_ip": "1.2.3.4"},
        {"row_index": 2, "source_type": "azure", "operationName": "Attach policy", "user": "alex", "resource_id": "admin-policy"},
        {"row_index": 3, "eventSource": "s3.amazonaws.com", "eventName": "GetObject", "_result": "SUCCESS", "user": "alex", "resource_id": "bucket/key"},
    ]
    nodes, edges, receipt = build_typed_projection(
        tenant_id="acme", case_id="case-1", rows=rows, ledger_head_hash="a" * 64,
    )
    types = {edge["edge_type"] for edge in edges}
    assert {"candidate_match", "configured_exposure", "observed_causal", "observed_interaction"} <= types
    assert all(edge["evidence_ids"] for edge in edges)
    assert receipt.node_ids == tuple(node["node_id"] for node in nodes)


def test_denied_network_action_does_not_become_observed_causal_edge():
    _nodes, edges, _receipt = build_typed_projection(
        tenant_id="acme", case_id="case-2", ledger_head_hash="b" * 64,
        rows=[{"source_type": "firewall", "src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "action": "deny"}],
    )
    assert not any(edge["edge_type"] == "observed_causal" for edge in edges)
    assert not any(edge["edge_type"] == "observed_interaction" for edge in edges)


def test_projection_preserves_distinct_clocks_and_calibration_receipt():
    nodes, edges, receipt = build_typed_projection(
        tenant_id="acme", case_id="case-time", ledger_head_hash="c" * 64,
        clock_calibration={"sysmon": {"correction_seconds": -10, "uncertainty_seconds": 2, "version": "clock-v2"}},
        rows=[{
            "source_type": "sysmon", "timestamp": "2026-08-19T09:11:10Z",
            "observed_at": "2026-08-19T09:11:12Z", "ingested_at": "2026-08-19T09:12:00Z",
            "known_at": "2026-08-19T09:13:00Z", "Image": "powershell.exe", "ParentImage": "cmd.exe",
        }],
    )
    assert nodes[0]["occurred_at"] == "2026-08-19T09:11:00Z"
    assert nodes[0]["observed_at"] == "2026-08-19T09:11:12Z"
    assert nodes[0]["known_at"] == "2026-08-19T09:13:00Z"
    assert edges[0]["observations"][0]["ingested_at"] == "2026-08-19T09:12:00Z"
    assert receipt.clock_calibration_hash


def test_evidence_id_is_content_addressed_and_prefers_explicit_id():
    row = {"row_index": 7, "user": "alex"}
    assert evidence_id_for_row("case-1", 0, row) == evidence_id_for_row("case-1", 99, dict(row))
    assert evidence_id_for_row("case-1", 0, {**row, "evidence_id": "ev-1"}) == "ev-1"
