from __future__ import annotations
import json

from src.api.case_view_v2 import _business_services, _canonical_hash, source_domain
from src.api.ingest_endpoints import _case_view_model


def test_case_view_is_honest_and_does_not_invent_causal_edges() -> None:
    model = _case_view_model(
        "assessment-1",
        "tenant-a",
        {"status": "ready", "stage": "complete", "percent": 100, "row_count": 2},
        {
            "org": "tenant-a",
            "all_rows": [
                {"id": "e1", "timestamp": "2026-08-18T00:00:00Z", "src_ip": "203.0.113.2", "user": "alex"},
                {"id": "e2", "timestamp": "2026-08-18T00:01:00Z", "src_ip": "203.0.113.2", "user": "alex"},
            ],
        },
    )
    assert model["schema_version"] == "janusec.case-evidence-view/v2"
    assert model["evidence"]["total"] == 2
    assert model["graph"]["edges"] == []
    assert {node["id"] for node in model["graph"]["nodes"]} == {"identity:alex", "network:203.0.113.2"}
    assert model["model_execution"]["provider"] == "deterministic"
    assert model["business_impact"] == []


def test_selected_case_preserves_milestones_actions_and_excludes_sibling_phase_metadata() -> None:
    from src.api.case_view_v2 import scope_case_view_to_partition
    from src.core.evidence_contract.case_partition import build_case_partitions

    rows = [
        {"row_index": 42, "timestamp": "2026-08-18T00:00:00Z", "user": "alex"},
        {"row_index": 99, "timestamp": "2026-08-17T00:00:00Z", "user": "sibling"},
    ]
    clusters = [
        {"cluster_id": "case-alex", "verdict": "VALIDATED_BREACH", "row_refs": [42],
         "phases": [{"phase_id": "powershell_staged_payload", "row_refs": [42], "mitre_techniques": ["T1059.001"]}],
         "immediate_actions": [{"title": "Review Alex's endpoint", "priority": "high"}]},
        {"cluster_id": "case-sibling", "verdict": "VALIDATED_BREACH", "row_refs": [99],
         "phases": [{"phase_id": "powershell_staged_payload", "row_refs": [99], "mitre_techniques": ["T1003"]}],
         "immediate_actions": [{"title": "Sibling-only action", "priority": "high"}]},
    ]
    partitions = build_case_partitions(
        tenant_id="tenant-a", assessment_id="assessment-selected", rows=rows,
        threat_cases=clusters, analysis_clusters=clusters,
    )
    partition = next(item for item in partitions if item["case_id"] == "case-alex")
    model = _case_view_model(
        "assessment-selected", "tenant-a",
        {"status": "ready", "stage": "ready", "percent": 100, "row_count": 2},
        {"all_rows": rows, "_derivation_rows": [rows[0]], "_selected_case_partition": partition,
         "threat_cases": clusters},
    )
    scoped = scope_case_view_to_partition(model, partition)
    milestones = scoped["attack_story"]["milestones"]
    assert scoped["evidence"]["truncated"] is False
    assert len(milestones) == 1
    assert milestones[0]["evidence_ids"] == partition["evidence_ids"]
    assert milestones[0]["mitre_techniques"] == ["T1059.001"]
    assert [item["decision"] for item in scoped["immediate_decisions"]] == ["Review Alex's endpoint"]
    assert scoped["action_plan"]["actions"], "Cited response actions must survive case scoping"
    assert "Sibling-only" not in json.dumps(scoped)


def test_case_view_uses_the_same_evidence_ids_as_partitions_and_projections() -> None:
    from src.core.evidence_contract.projection_builder import evidence_id_for_row
    from src.core.evidence_contract.semantic_adapters import normalize_semantics

    row = {"row_index": 42, "timestamp": "2026-08-18T00:00:00Z", "user": "alex"}
    model = _case_view_model(
        "assessment-ids", "tenant-a",
        {"status": "ready", "stage": "complete", "percent": 100, "row_count": 1},
        {"all_rows": [row]},
    )
    expected = evidence_id_for_row("assessment-ids", 42, normalize_semantics(dict(row)))
    assert model["evidence"]["rows"][0]["id"] == expected


def test_case_view_preview_uses_hydrated_case_rows_not_assessment_preview() -> None:
    model = _case_view_model(
        "assessment-case-preview", "tenant-a",
        {"status": "ready", "stage": "complete", "percent": 100, "row_count": 1000},
        {
            "all_rows": [{"row_index": 1, "user": "sibling"}],
            "_derivation_rows": [
                {"row_index": 900, "user": "selected"},
                {"row_index": 901, "user": "selected"},
            ],
        },
    )
    assert [item["raw"]["row_index"] for item in model["evidence"]["rows"]] == [900, 901]


def test_case_view_reports_absent_evidence_as_gap() -> None:
    model = _case_view_model(
        "assessment-empty",
        "tenant-a",
        {"status": "ready", "stage": "complete", "percent": 100, "row_count": 0},
        {},
    )
    assert model["posture"]["evidence_completeness"] == 0.0
    assert "No telemetry evidence" in model["coverage_gaps"][0]


def test_case_view_keeps_cross_domain_sources_distinct() -> None:
    model = _case_view_model(
        "assessment-domains",
        "tenant-a",
        {"status": "ready", "stage": "complete", "percent": 100, "row_count": 5},
        {
            "all_rows": [
                {"id": "mail", "source": "m365.unified_audit", "timestamp": "2026-01-01T00:00:00Z"},
                {"id": "aws", "provider": "aws_cloudtrail", "timestamp": "2026-01-01T00:00:01Z"},
                {"id": "ali", "provider": "alibaba_actiontrail", "timestamp": "2026-01-01T00:00:02Z"},
                {"id": "ebpf", "source_type": "ebpf", "timestamp": "2026-01-01T00:00:03Z"},
                {"id": "ids", "source": "suricata.eve.json", "timestamp": "2026-01-01T00:00:04Z"},
            ]
        },
    )
    domains = {item["domain"] for item in model["source_domains"]}
    assert {"email", "cloud_aws", "cloud_alibaba", "endpoint_ebpf", "network_suricata"} <= domains


def test_case_view_normalizes_legacy_business_service_metadata(monkeypatch) -> None:
    from src.core.evidence_contract.signed_snapshots import sign_snapshot

    monkeypatch.setenv("JANUSEC_SNAPSHOT_HMAC_KEY", "test-secret")
    supplied = {"service": "Customer payments", "impact": "Availability not yet established"}
    normalized = _business_services(supplied)
    receipt = sign_snapshot(
        kind="cmdb", tenant_id="tenant-a",
        payload={"source": "service-now", "mapping_version": "v3", "mapped_services_hash": _canonical_hash(normalized)},
        source="service-now", version="v3", valid_from="2026-08-19T00:00:00Z", key="test-secret",
    )
    model = _case_view_model(
        "assessment-service",
        "tenant-a",
        {"status": "ready", "stage": "complete", "percent": 100, "row_count": 0},
        {
            "business_impact": supplied,
            "cmdb_mapping_receipt": receipt,
        },
    )
    assert model["business_impact"][0]["id"] == "service-1"
    assert model["business_impact"][0]["name"] == "Customer payments"
    assert model["business_impact"][0]["status"] == "not_assessed"


def test_case_view_does_not_promote_unreceipted_business_metadata() -> None:
    model = _case_view_model(
        "assessment-service-unmapped", "tenant-a",
        {"status": "ready", "stage": "complete", "percent": 100, "row_count": 0},
        {"business_impact": {"service": "Customer payments", "impact": "Unverified"}},
    )
    assert model["business_impact"] == []
    assert any("without a valid CMDB" in gap for gap in model["coverage_gaps"])


def test_case_view_exposes_case_pack_receipts_and_infrastructure_freshness(monkeypatch) -> None:
    from src.core.evidence_contract.signed_snapshots import sign_snapshot

    monkeypatch.setenv("JANUSEC_SNAPSHOT_HMAC_KEY", "test-secret")
    iam = sign_snapshot(
        kind="iam", tenant_id="tenant-a", payload={"allowed_paths": [["user:a", "role:b"]]},
        source="sandbox", version="1", valid_from="2026-08-19T00:00:00Z", key="test-secret",
    )
    model = _case_view_model(
        "assessment-proof", "tenant-a",
        {"status": "ready", "stage": "complete", "percent": 100, "row_count": 0},
        {
            "authorization_snapshot": iam,
            "evidence_pack_receipts_by_case": {
                "assessment-proof": [{"pack_id": "ep2_test", "content_hash": "a" * 64}],
            },
        },
    )
    context = model["report_context"]
    assert context["evidence_pack_receipts"][0]["pack_id"] == "ep2_test"
    assert context["infrastructure_truth"]["iam"]["status"] == "verified"
    assert context["infrastructure_truth"]["topology"]["status"] == "snapshot_missing"


def test_source_domain_taxonomy_covers_supported_enterprise_telemetry() -> None:
    samples = {
        "email": {"source": "proofpoint_email"},
        "cloud_aws": {"provider": "aws_cloudtrail"},
        "cloud_azure": {"source_type": "azure_activity"},
        "cloud_gcp": {"provider": "gcp_audit"},
        "cloud_alibaba": {"provider": "alibaba_actiontrail"},
        "virtualization_nutanix": {"source": "nutanix_prism"},
        "virtualization_vmware": {"source": "vmware_vcenter"},
        "infrastructure_hpe": {"source": "hpe_oneview"},
        "endpoint_ebpf": {"source_type": "ebpf_tetragon"},
        "endpoint_sysmon": {"source": "sysmon"},
        "network_firewall": {"source": "paloalto_firewall"},
        "network_suricata": {"source": "suricata_eve.json"},
    }
    assert {name: source_domain(row) for name, row in samples.items()} == {name: name for name in samples}


def test_phase_milestones_use_supporting_event_time_and_canonical_row_ids() -> None:
    from src.api.case_view_v2 import _milestones, _phase_milestones
    from src.core.evidence_contract.projection_builder import evidence_id_for_row
    from src.core.evidence_contract.semantic_adapters import normalize_semantics

    rows = {
        "101": {"row_index": 101, "timestamp": "2026-04-12T01:00:00Z", "source_type": "iam"},
        "202": {"row_index": 202, "timestamp": "2026-04-26T02:00:00Z", "source_type": "endpoint"},
    }
    row_map = {
        ref: evidence_id_for_row("assessment-time", int(ref), normalize_semantics(dict(row)))
        for ref, row in rows.items()
    }
    raw = _milestones([{
        "cluster_id": "campaign", "verdict": "VALIDATED_BREACH",
        "time_window": {"start": "2026-04-26T02:00:00Z"},
        "phases": [
            {"phase_id": "oauth_device_code", "case_role": "initial_access", "row_refs": [101]},
            {"phase_id": "kerberos_ticket_forgery", "case_role": "persistence", "row_refs": [202]},
        ],
    }], row_map, rows)
    milestones = _phase_milestones(raw, [])
    assert [item["phase_id"] for item in milestones] == ["oauth_device_code", "kerberos_ticket_forgery"]
    assert milestones[0]["occurred_at"] == "2026-04-12T01:00:00Z"
    assert milestones[0]["time_basis"] == "supporting_evidence_event_time"
    assert milestones[0]["evidence_ids"] == [row_map["101"]]

def test_partition_scope_excludes_sibling_evidence_and_selects_case_projection():
    from src.api.case_view_v2 import scope_case_view_to_partition

    view = {
        "case": {"id": "assessment-1", "tenant_id": "tenant-a"},
        "claims": [
            {"id": "a", "supporting_evidence_ids": ["e-a"]},
            {"id": "b", "supporting_evidence_ids": ["e-b"]},
        ],
        "attack_story": {"milestones": [
            {"id": "ma", "evidence_ids": ["e-a"]},
            {"id": "mb", "evidence_ids": ["e-b"]},
        ], "entry_vector": {"title": "SIBLING_ONLY", "evidence_ids": ["e-b"]},
           "blast_radius": {"title": "SIBLING_ONLY", "evidence_ids": ["e-b"]}},
        "corrective_actions": [{"action": "SIBLING_ONLY", "case_id": "case-b"}],
        "hypotheses": [{"title": "SIBLING_ONLY", "evidence_ids": ["e-a", "e-b"]}],
        "authorization_paths": [],
        "evidence": {"rows": [{"id": "e-a"}, {"id": "e-b"}], "total": 2},
        "timeline": [{"evidence_id": "e-a"}, {"evidence_id": "e-b"}],
        "posture": {"evidence_completeness": 0.01},
        "coverage_gaps": [],
        "breach_summary": {},
        "report_context": {},
        "_graph_projections_by_case": {
            "case-a": {"status": "current", "receipt": {"projection_id": "gp-a", "content_hash": "rh-a"}}
        },
        "_evidence_pack_receipts_by_case": {
            "case-a": [{"pack_id": "ep-a", "content_hash": "pa"}],
            "case-b": [{"pack_id": "ep-b", "content_hash": "pb"}],
        },
    }
    partition = {
        "case_id": "case-a", "partition_id": "cp-a", "content_hash": "ph-a",
        "verdict": "VALIDATED_BREACH", "evidence_ids": ["e-a"], "episodes": [],
    }
    scoped = scope_case_view_to_partition(view, partition)
    assert scoped["case"]["id"] == "case-a"
    assert [item["id"] for item in scoped["claims"]] == ["a"]
    assert [item["id"] for item in scoped["evidence"]["rows"]] == ["e-a"]
    assert scoped["posture"]["evidence_completeness"] == 1.0
    assert scoped["report_context"]["graph_projection_id"] == "gp-a"
    assert [item["pack_id"] for item in scoped["report_context"]["evidence_pack_receipts"]] == ["ep-a"]
    assert "_evidence_pack_receipts_by_case" not in scoped
    assert "SIBLING_ONLY" not in json.dumps(scoped)


def test_partition_scope_reports_missing_case_evidence_refs():
    from src.api.case_view_v2 import scope_case_view_to_partition

    view = {
        "case": {"id": "assessment-1"}, "claims": [],
        "attack_story": {"milestones": []}, "authorization_paths": [],
        "evidence": {"rows": [{"id": "e-a"}]}, "timeline": [],
        "breach_summary": {}, "report_context": {}, "posture": {}, "coverage_gaps": [],
    }
    partition = {
        "case_id": "case-a", "partition_id": "cp-a", "content_hash": "ph-a",
        "verdict": "VALIDATED_BREACH", "evidence_ids": ["e-a", "e-missing"], "episodes": [],
    }
    scoped = scope_case_view_to_partition(view, partition)
    assert scoped["posture"]["evidence_completeness"] == 0.5
    assert scoped["evidence"]["truncated"] is True
    assert any("1 case evidence" in gap for gap in scoped["coverage_gaps"])
