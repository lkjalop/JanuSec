from __future__ import annotations

from datetime import datetime

import pytest

from src.core.agent_harness import GuardedTool, SessionLog
from src.core.assessment_run import standard_dag
from src.core.evidence_contract.correlation import validate_edges
from src.core.evidence_contract.object_store import S3WORMObjectStore
from src.core.evidence_contract.retrieval import compile_evidence_pack


class _S3:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.puts = []

    def get_object_lock_configuration(self, **kwargs):
        return {"ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled" if self.enabled else "Disabled"}}

    def put_object(self, **kwargs):
        self.puts.append(kwargs)


def test_s3_worm_requires_object_lock_and_sets_compliance_retention(tmp_path) -> None:
    with pytest.raises(Exception, match="Object Lock"):
        S3WORMObjectStore("bucket", client=_S3(False))
    client = _S3()
    store = S3WORMObjectStore("bucket", client=client, retention_days=30)
    stored = store.put_bytes(b"evidence", tenant_id="acme", case_id="case-1", legal_hold=True)
    assert stored.locator.startswith("s3://bucket/evidence/acme/case-1/")
    assert client.puts[0]["ObjectLockMode"] == "COMPLIANCE"
    assert client.puts[0]["ObjectLockLegalHoldStatus"] == "ON"
    assert isinstance(client.puts[0]["ObjectLockRetainUntilDate"], datetime)


def test_standard_dag_is_shared_and_ordered() -> None:
    dag = standard_dag("acme", "case-1", "connector")
    assert dag.topological_order == ("capture", "parse", "normalize", "correlate", "retrieve", "assess", "report")


def test_weak_identifier_cannot_be_promoted_to_causal_edge() -> None:
    accepted, excluded = validate_edges(
        [
            {
                "source": "a",
                "target": "b",
                "edge_type": "observed_causal",
                "evidence_ids": ["e1"],
                "match_basis": ["ip"],
            },
            {"source": "a", "target": "b", "edge_type": "candidate_match", "evidence_ids": [], "match_basis": ["ip"]},
        ]
    )
    assert [edge["edge_type"] for edge in accepted] == ["candidate_match"]
    assert excluded[0]["reason"] == "weak_identifiers_only_support_candidate_match"


def test_evidence_pack_is_deterministic_and_exposes_temporal_exclusions() -> None:
    records = [
        {
            "evidence_id": "e1",
            "content_hash": "a" * 64,
            "known_at": "2026-08-18T10:00:00Z",
            "payload": {"user": "alex"},
        },
        {
            "evidence_id": "e2",
            "content_hash": "b" * 64,
            "known_at": "2026-08-18T11:00:00Z",
            "payload": {"user": "alex"},
        },
    ]
    kwargs = dict(
        tenant_id="acme",
        case_id="case-1",
        query="alex",
        identifiers=["alex"],
        records=records,
        as_known_at="2026-08-18T10:30:00Z",
    )
    first = compile_evidence_pack(**kwargs)
    second = compile_evidence_pack(**kwargs)
    assert first.pack_id == second.pack_id
    assert {item["id"] for item in first.excluded_candidates} == {"e2"}
    assert next(step for step in first.retrieval_trace if step["stage"] == "dense_documents")["status"] == "provider_not_configured"
    assert first.verification["action"] == "accept"


def test_causal_traversal_promotes_evidence_and_corrective_step_finds_conflict() -> None:
    records = [
        {"evidence_id": "e1", "tenant_id": "acme", "case_id": "c1", "occurred_at": "2026-08-18T10:01:00Z", "payload": {"user": "alex"}},
        {"evidence_id": "e2", "tenant_id": "acme", "case_id": "c1", "occurred_at": "2026-08-18T10:00:00Z", "payload": {"host": "db01"}},
        {"evidence_id": "e3", "tenant_id": "acme", "case_id": "c1", "occurred_at": "2026-08-18T10:02:00Z", "payload": {"result": "denied"}},
    ]
    pack = compile_evidence_pack(
        tenant_id="acme",
        case_id="c1",
        query="alex",
        identifiers=["alex"],
        records=records,
        edges=[
            {"source": "e1", "target": "e2", "edge_type": "observed_causal", "evidence_ids": ["e1", "e2"], "match_basis": ["process_lineage"]},
            {"source": "e3", "target": "e1", "edge_type": "contradicts", "evidence_ids": ["e3"], "match_basis": ["result"]},
        ],
        max_hops=1,
    )
    assert {row["evidence_id"] for row in pack.supporting_evidence} >= {"e1", "e2"}
    assert {row["evidence_id"] for row in pack.contradicting_evidence} == {"e3"}
    assert pack.verification["action"] == "refine"
    assert pack.verification["temporal_conflict_count"] == 1


def test_candidate_match_never_promotes_or_crosses_tenant() -> None:
    records = [
        {"evidence_id": "e1", "tenant_id": "acme", "case_id": "c1", "payload": {"ip": "1.2.3.4"}},
        {"evidence_id": "e2", "tenant_id": "acme", "case_id": "c1", "payload": {"user": "unrelated"}},
        {"evidence_id": "e3", "tenant_id": "other", "case_id": "c1", "payload": {"ip": "1.2.3.4"}},
    ]
    pack = compile_evidence_pack(
        tenant_id="acme",
        case_id="c1",
        query="address",
        identifiers=["1.2.3.4"],
        records=records,
        edges=[{"source": "e1", "target": "e2", "edge_type": "candidate_match", "evidence_ids": [], "match_basis": ["ip"]}],
    )
    assert {row["evidence_id"] for row in pack.supporting_evidence} == {"e1"}
    assert pack.verification["candidate_edges_not_promoted"] == 1
    assert any(item["reason"] == "cross_tenant_record" for item in pack.excluded_candidates)


def test_evidence_pack_v21_separates_case_evidence_from_context_and_binds_projection() -> None:
    records = [{"evidence_id": "e1", "tenant_id": "acme", "case_id": "c1", "payload": {"user": "alex"}}]
    receipt = {"projection_id": "gp-1", "content_hash": "a" * 64, "ledger_head_hash": "b" * 64}
    pack = compile_evidence_pack(
        tenant_id="acme", case_id="c1", query="alex", identifiers=["alex"], records=records,
        dense_document_retriever=lambda *_args: [{"document_id": "doc-1", "text": "control guidance"}],
        temporal_prior_retriever=lambda *_args: [{"source_case_id": "old-case", "summary": "similar"}],
        projection_receipt=receipt,
        cmdb_mapping_receipt={"source": "cmdb", "mapping_version": "v1", "content_hash": "c" * 64},
        ppr_candidates=[{"node_id": "hub-ip"}],
    )
    rendered = pack.to_dict()
    assert rendered["schema_version"] == "janusec.evidence-pack/v2.1"
    assert rendered["case_evidence"] == rendered["supporting_evidence"]
    assert len(rendered["retrieved_context"]) == 2
    assert all(step.get("promoted_to_case_evidence") == 0 for step in rendered["retrieval_trace"] if step["stage"] in {"dense_document_context", "temporal_prior_cases"})
    assert rendered["graph_projection_id"] == "gp-1"
    assert rendered["excluded_ppr_candidates"][0]["reason"] == "shadow_retrieval_not_promoted"


def test_corrective_policy_reports_child_observed_before_parent() -> None:
    from src.core.evidence_contract.contradiction_policies import process_parent_time_policy

    child = {
        "evidence_id": "child", "user": "james", "hostname": "host-1", "process_id": 20,
        "parent_process_id": 10, "timestamp": "2026-05-08T09:06:30Z",
    }
    parent = {
        "evidence_id": "parent", "user": "james", "hostname": "host-1", "process_id": 10,
        "timestamp": "2026-05-08T09:06:55Z",
    }
    result = process_parent_time_policy([child], [child, parent], [])
    assert result[0]["status"] == "clock_or_order_conflict"
    assert result[0]["delta_seconds"] == 25


def test_corrective_policy_uses_name_only_as_guarded_lineage_conflict() -> None:
    from src.core.evidence_contract.contradiction_policies import process_parent_time_policy

    child = {
        "evidence_id": "child", "user_name": "james", "device_id": "host-1", "process_id": 20,
        "parent_process_id": 999, "parent_process_name": "cmd.exe", "image_file_name": "powershell.exe",
        "command_line": "powershell.exe -EncodedCommand AAA -WindowStyle Hidden",
        "timestamp": "2026-05-08T09:06:30Z",
    }
    parent = {
        "evidence_id": "parent", "user_name": "james", "device_id": "host-1", "process_id": 10,
        "image_file_name": "cmd.exe", "timestamp": "2026-05-08T09:06:55Z",
    }
    result = process_parent_time_policy([child], [child, parent], [])
    assert result[0]["match_basis"] == "parent_process_name_without_matching_pid"


def test_agent_session_is_hash_chained_forkable_and_tools_are_guarded(tmp_path) -> None:
    log = SessionLog(tmp_path)
    first = log.append(
        tenant_id="acme", case_id="case-1", session_id="s1", event_type="prompt", payload={"text": "inspect"}
    )
    second = log.append(
        tenant_id="acme", case_id="case-1", session_id="s1", event_type="model", payload={"claim": "candidate"}
    )
    assert second.previous_hash == first.event_hash
    child = log.fork(tenant_id="acme", case_id="case-1", session_id="s1", at_sequence=0)
    assert log.read("acme", child)[0]["event_type"] == "session_forked"
    tool = GuardedTool("contain", lambda args: {"ok": args["id"]}, "containment:write", mutating=True)
    with pytest.raises(PermissionError, match="approval"):
        tool.invoke({"id": "host-1"}, scopes={"containment:write"})
    assert tool.invoke({"id": "host-1"}, scopes={"containment:write"}, approved=True)["ok"] == "host-1"
