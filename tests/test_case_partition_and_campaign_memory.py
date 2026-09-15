from __future__ import annotations

from src.core.chrono.campaign_accumulator import accumulate_low_and_slow
from src.core.chrono.sketch_store import ChronoSketchStore
from src.core.evidence_contract.case_partition import build_case_partitions
from src.core.evidence_contract.episodic_hippograph import build_episode_shadow_graph, retrieve_episode_candidates
from src.core.evidence_contract.path_validation import validate_investigation_paths
from src.core.evidence_contract.projection_builder import evidence_id_for_row
from src.core.evidence_contract.retrieval import compile_evidence_pack
from src.core.evidence_contract.threat_coverage import assess_threat_coverage
from src.core.model_escalation import decide_frontier_escalation
from src.api.case_intelligence_endpoints import _scope_view_to_partition


def _rows():
    return [
        {"row_index": 10, "timestamp": "2026-05-01T01:10:00Z", "user": "james", "host": "ws-james", "source_type": "endpoint", "phase_id": "initial_access", "action_outcome": "success"},
        {"row_index": 20, "timestamp": "2026-05-01T01:20:00Z", "user": "james", "host": "ws-james", "source_type": "network", "phase_id": "c2", "action_outcome": "success"},
        {"row_index": 30, "timestamp": "2026-05-02T02:00:00Z", "user": "wei", "source_type": "email", "phase_id": "collection", "action_outcome": "success"},
        {"row_index": 40, "timestamp": "2026-05-03T02:00:00Z", "user": "james", "source_type": "cloud", "phase_id": "collection", "action_outcome": "denied"},
    ]


def test_case_partitions_are_stable_separate_and_multiresolution():
    rows = _rows()
    partitions = build_case_partitions(
        tenant_id="tenant-a", assessment_id="assessment-1", rows=rows,
        threat_cases=[
            {"case_id": "james", "verdict": "VALIDATED_BREACH", "row_refs": [10, 20], "supporting_cluster_ids": ["james-support"], "entity_roles": [{"role": "actor", "entity": "james"}], "phases": [{"phase_id": "initial_access", "row_refs": [10]}, {"phase_id": "c2", "row_refs": [20]}]},
            {"case_id": "wei", "verdict": "SUSPECTED_BREACH", "row_refs": [30]},
        ],
        analysis_clusters=[{"cluster_id": "james-support", "row_refs": [40], "phases": [{"phase_id": "collection", "row_refs": [40]}]}],
    )
    assert [item["case_id"] for item in partitions] == ["james", "wei"]
    assert partitions[0]["row_refs"] == [10, 20, 40]
    assert partitions[1]["row_refs"] == [30]
    assert partitions[0]["evidence_count"] == 3
    assert partitions[0]["source_count"] == 3
    assert partitions[0]["source_artifacts"] == ["cloud", "endpoint", "network"]
    assert partitions[0]["title"] == "james · Confirmed breach · 3 phase(s) · 3 evidence row(s) · 3 telemetry source(s)"
    assert {item["resolution"] for item in partitions[0]["episodes"]} == {"hour", "day", "campaign"}
    hourly_phases = {
        phase for item in partitions[0]["episodes"] if item["resolution"] == "hour"
        for phase in item["phase_ids"]
    }
    assert hourly_phases == {"initial_access", "c2", "collection"}
    assert partitions[0]["content_hash"] == build_case_partitions(
        tenant_id="tenant-a", assessment_id="assessment-1", rows=rows,
        threat_cases=[{"case_id": "james", "verdict": "VALIDATED_BREACH", "row_refs": [10, 20], "supporting_cluster_ids": ["james-support"], "entity_roles": [{"role": "actor", "entity": "james"}], "phases": [{"phase_id": "initial_access", "row_refs": [10]}, {"phase_id": "c2", "row_refs": [20]}]}],
        analysis_clusters=[{"cluster_id": "james-support", "row_refs": [40], "phases": [{"phase_id": "collection", "row_refs": [40]}]}],
    )[0]["content_hash"]


def test_case_partition_infers_supporting_cluster_when_ids_match():
    partitions = build_case_partitions(
        tenant_id="tenant-a",
        assessment_id="assessment-1",
        rows=_rows(),
        threat_cases=[{"case_id": "james", "verdict": "VALIDATED_BREACH", "row_refs": [10]}],
        analysis_clusters=[{"cluster_id": "james", "row_refs": [20]}],
    )

    assert partitions[0]["supporting_cluster_ids"] == ["james"]
    assert partitions[0]["row_refs"] == [10, 20]


def test_case_partition_preserves_observed_network_source_and_destination_roles():
    partitions = build_case_partitions(
        tenant_id="tenant-a", assessment_id="assessment-network",
        rows=[{"row_index": 7, "src_ip": "185.234.219.47", "dst_ip": "52.94.76.5"}],
        threat_cases=[{"case_id": "crawler", "verdict": "VALIDATED_BREACH", "row_refs": [7]}],
        analysis_clusters=[],
    )
    roles = {(item["role"], item["entity"]) for item in partitions[0]["roles"]}
    assert ("instrument", "185.234.219.47") in roles
    assert ("destination", "52.94.76.5") in roles


def test_case_partition_keeps_asrep_requested_account_as_target_not_actor():
    partitions = build_case_partitions(
        tenant_id="tenant-a", assessment_id="assessment-kerberos",
        rows=[{
            "row_index": 9, "source_type": "windows_security", "windows_event_id": "4768",
            "pre_auth_type": "0", "account_name": "svc_database", "client_address": "10.0.0.8",
        }],
        threat_cases=[{
            "case_id": "roast", "verdict": "VALIDATED_BREACH", "row_refs": [9],
            "entity_roles": [{"role": "actor", "entity": "observed.requester"}],
        }],
        analysis_clusters=[],
    )
    roles = {(item["role"], item["entity"]) for item in partitions[0]["roles"]}
    assert ("target", "svc_database") in roles
    assert ("actor", "svc_database") not in roles


def test_case_scoped_pack_performs_second_pass_corrective_retrieval():
    rows = _rows()
    records = []
    for index, row in enumerate(rows):
        records.append({
            **row, "tenant_id": "tenant-a", "case_id": "james",
            "record_type": "normalized_evidence_projection",
            "evidence_id": evidence_id_for_row("assessment-1", index, row),
        })
    partition = {
        "case_id": "james", "content_hash": "partition-hash",
        "evidence_ids": [record["evidence_id"] for record in records],
        "episodes": [{"episode_id": "episode-1"}],
    }
    pack = compile_evidence_pack(
        tenant_id="tenant-a", case_id="james", query="successful access",
        identifiers=["ws-james"], records=records, case_partition=partition,
        episodes=partition["episodes"], limit=20,
    )
    assert pack.case_partition_hash == "partition-hash"
    assert pack.question_id and pack.question_id.startswith("question_")
    assert pack.episode_ids == ("episode-1",)
    assert any(item.get("action_outcome") == "denied" for item in pack.corrective_evidence)
    corrective_trace = next(item for item in pack.retrieval_trace if item["stage"] == "corrective_retrieval")
    assert corrective_trace["changed_evidence_set"] is True
    assert pack.verification["action"] == "refine"


def test_corrective_rag_acceptance_requires_changed_ids_and_measured_recall_gain():
    records = [{
        **row, "tenant_id": "tenant-a", "case_id": "james",
        "record_type": "normalized_evidence_projection",
        "evidence_id": evidence_id_for_row("assessment-acceptance", index, row),
    } for index, row in enumerate(_rows())]
    denied_id = records[3]["evidence_id"]
    pack = compile_evidence_pack(
        tenant_id="tenant-a", case_id="james", query="successful access",
        identifiers=["ws-james"], records=records,
        expected_evidence_ids=[records[0]["evidence_id"], records[1]["evidence_id"], denied_id],
    )
    acceptance = pack.corrective_acceptance
    assert acceptance["added_evidence_ids"] == [denied_id]
    assert acceptance["corrected_evidence_recall"] > acceptance["initial_evidence_recall"]
    assert acceptance["accepted"] is True
    assert acceptance["outcome"] == "improved"


def test_corrective_rag_abstains_when_second_query_adds_no_eligible_evidence():
    row = {
        "tenant_id": "tenant-a", "case_id": "james", "record_type": "normalized_evidence_projection",
        "evidence_id": "e1", "user": "james", "action_outcome": "success",
    }
    pack = compile_evidence_pack(
        tenant_id="tenant-a", case_id="james", query="successful access",
        identifiers=["james"], records=[row], expected_evidence_ids=["e1"],
    )
    assert pack.corrective_acceptance["changed_evidence_set"] is False
    assert pack.corrective_acceptance["accepted"] is False
    assert pack.corrective_acceptance["outcome"] == "abstain_no_evidence_delta"


def test_path_validation_rejects_causal_edge_whose_evidence_is_outside_case():
    result = validate_investigation_paths([
        {"source": "process:a", "target": "process:b", "edge_type": "observed_causal", "evidence_ids": ["missing"], "match_basis": ["process_parentage"]}
    ], records_by_id={})
    assert result["validated_edges"] == []
    assert result["rejected_edges"][0]["reason"] == "causal_edge_evidence_not_present_in_case"
    assert len(result["gaps"]) == 2


def test_low_and_slow_accumulation_preserves_weak_multiday_signal_without_verdict():
    rows = [
        {"timestamp": "2026-05-01T01:00:00Z", "user": "quiet", "source_type": "endpoint", "phase_id": "recon", "triage_score": 0.2},
        {"timestamp": "2026-05-03T01:00:00Z", "user": "quiet", "source_type": "network", "phase_id": "c2", "triage_score": 0.2},
        {"timestamp": "2026-05-08T01:00:00Z", "user": "quiet", "source_type": "cloud", "phase_id": "collection", "triage_score": 0.2},
    ]
    result = accumulate_low_and_slow(rows)
    assert len(result) == 1
    assert result[0]["active_days"] == 3
    assert result[0]["epistemic_status"] == "candidate_not_breach_truth"
    assert "verdict" not in result[0]


def test_emerging_threat_coverage_and_frontier_escalation_are_explicit():
    coverage = assess_threat_coverage([
        {"capabilities": ["model_digest", "prompt_audit", "tool_invocation"]}
    ], "ai_model_or_agent_compromise")
    assert coverage["status"] == "coverage_gaps"
    assert any(item["capability"] == "data_boundary" and item["status"] == "missing" for item in coverage["capabilities"])
    escalation = decide_frontier_escalation({
        "attribution_quality": 0.5, "evidence_recall": 0.4,
        "unsupported_claim_rate": 0.2, "case_partition_count": 3, "case_scoped": False,
    }, external_approved=False)
    assert escalation["required"] is True
    assert escalation["route"] == "analyst_review"
    assert escalation["external_approval_required"] is True


def test_chronograph_time_pyramid_and_hippograph_remain_descriptive_shadow_state():
    chrono = ChronoSketchStore()
    reference = 1_800_000_000.0
    chrono.increment("user", "james", "recon", 1, ts=reference - 7200)
    chrono.increment("user", "james", "recon", 2, ts=reference - 90000)
    pyramid = chrono.multi_resolution_summary("user", "james", "recon", reference_ts=reference)
    assert [item["window_seconds"] for item in pyramid["windows"]] == [3600, 86400, 604800, 2592000]
    assert pyramid["windows"][-1]["sum"] == 3

    episodes = [
        {"episode_id": "e1", "case_id": "james", "entity_ids": ["james", "ws-james"], "phase_ids": ["initial_access"], "source_domains": ["endpoint"], "interval_end": "2026-05-01T00:00:00Z"},
        {"episode_id": "e2", "case_id": "james", "entity_ids": ["james", "ws-james"], "phase_ids": ["initial_access"], "source_domains": ["endpoint", "network"], "interval_start": "2026-05-02T00:00:00Z"},
        {"episode_id": "e3", "case_id": "wei", "entity_ids": ["james"], "phase_ids": ["initial_access"], "source_domains": ["endpoint"]},
    ]
    shadow = build_episode_shadow_graph(episodes)
    assert shadow["status"] == "shadow_not_evidence"
    assert any(item["reason"] == "cross_case_association_disabled" for item in shadow["excluded"])
    candidates = retrieve_episode_candidates(shadow, ["e1"])
    assert candidates[0]["episode_id"] == "e2"
    assert candidates[0]["reason"].endswith("requires_local_corroboration")


def test_model_context_is_physically_reduced_to_selected_case_partition():
    view = {
        "case": {"id": "assessment-1"},
        "claims": [
            {"id": "j", "supporting_evidence_ids": ["ev-j"]},
            {"id": "w", "supporting_evidence_ids": ["ev-w"]},
        ],
        "attack_story": {"milestones": [
            {"id": "mj", "evidence_ids": ["ev-j"]},
            {"id": "mw", "evidence_ids": ["ev-w"]},
        ]},
        "authorization_paths": [],
        "evidence": {"rows": [{"id": "ev-j"}, {"id": "ev-w"}], "total": 2},
        "timeline": [{"evidence_id": "ev-j"}, {"evidence_id": "ev-w"}],
        "breach_summary": {},
    }
    scoped = _scope_view_to_partition(view, {
        "case_id": "james", "partition_id": "cp-j", "content_hash": "hash-j",
        "title": "James intrusion", "verdict": "VALIDATED_BREACH",
        "evidence_ids": ["ev-j"], "episodes": [{"episode_id": "e-j"}],
    })
    assert scoped["case"]["id"] == "james"
    assert [item["id"] for item in scoped["claims"]] == ["j"]
    assert [item["id"] for item in scoped["evidence"]["rows"]] == ["ev-j"]
    assert scoped["timeline"] == [{"evidence_id": "ev-j"}]
    assert "ev-w" not in str(scoped)
