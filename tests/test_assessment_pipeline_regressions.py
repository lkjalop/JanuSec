from __future__ import annotations

from src.core.ingest import assessment_worker
from src.core.ingest.cluster_narrator import _apply_narrative_to_cluster, narrate_cluster


def test_llm_narrative_cannot_downgrade_deterministic_verdict():
    cluster = {
        "cluster_id": "c1",
        "verdict": "VALIDATED_BREACH",
        "final_verdict": "VALIDATED_BREACH",
        "confidence": 0.91,
    }
    narrative = {
        "verdict": "REQUIRES_INVESTIGATION",
        "confidence": 0.42,
        "kill_chain_stage": "execution",
        "kill_chain_stages": ["execution"],
        "ioc_summary": "weak model output",
        "attack_narrative": "model was uncertain",
        "next_steps": [],
        "fp_indicators": [],
        "evidence_refs": [1],
    }

    _apply_narrative_to_cluster(cluster, narrative, upgrade_only=True)

    assert cluster["final_verdict"] == "VALIDATED_BREACH"
    assert cluster["verdict"] == "VALIDATED_BREACH"
    assert cluster["confidence"] == 0.91
    assert cluster["llm_narrative"] == narrative


def test_llm_narrative_can_upgrade_uncertain_cluster():
    cluster = {
        "cluster_id": "c2",
        "verdict": "REQUIRES_INVESTIGATION",
        "final_verdict": "REQUIRES_INVESTIGATION",
        "confidence": 0.4,
    }
    narrative = {
        "verdict": "SUSPECTED_BREACH",
        "confidence": 0.77,
        "kill_chain_stage": "c2",
        "kill_chain_stages": ["c2", "exfiltration"],
        "ioc_summary": "correlated C2",
        "attack_narrative": "C2 activity followed access.",
        "next_steps": [],
        "fp_indicators": [],
        "evidence_refs": [1, 2],
    }

    _apply_narrative_to_cluster(cluster, narrative, upgrade_only=True)

    assert cluster["final_verdict"] == "SUSPECTED_BREACH"
    assert cluster["verdict"] == "SUSPECTED_BREACH"
    assert cluster["confidence"] == 0.77
    assert cluster["kill_chain_stages"] == ["c2", "exfiltration"]


def test_known_pentest_cluster_skips_llm_and_preserves_benign_verdict():
    cluster = {
        "cluster_id": "pentest-1",
        "cluster_kind": "pentest",
        "verdict": "BENIGN_EXPECTED",
        "final_verdict": "BENIGN_EXPECTED",
        "confidence": 0.92,
        "lead_description": "Authorized red-team activity under engagement ROE",
        "row_count": 3,
    }

    narrative = narrate_cluster(cluster, [], assessment_id="test")

    assert narrative["_narrator_source"] == "deterministic_threat_case"
    assert cluster["final_verdict"] == "BENIGN_EXPECTED"
    assert cluster["verdict"] == "BENIGN_EXPECTED"
    assert cluster["confidence"] == 0.92


def test_breach_gate_includes_suspected_and_correlated_investigation_clusters():
    assert assessment_worker._is_breach_cluster({"final_verdict": "SUSPECTED_BREACH"})
    assert assessment_worker._is_breach_cluster(
        {"final_verdict": "REQUIRES_INVESTIGATION", "sources": ["okta", "edr"]}
    )
    assert assessment_worker._is_breach_cluster(
        {"final_verdict": "REQUIRES_INVESTIGATION", "row_count": 50}
    )
    assert not assessment_worker._is_breach_cluster(
        {"final_verdict": "BENIGN_EXPECTED", "row_count": 500, "sources": ["okta", "edr"]}
    )


def test_kill_chain_seed_uses_action_process_and_url_fields():
    assessment: dict = {}
    clusters = [
        {
            "cluster_id": "breach-1",
            "final_verdict": "VALIDATED_BREACH",
            "row_refs": [1, 2],
            "row_count": 2,
        }
    ]
    rows = [
        {
            "row_index": 1,
            "timestamp": "2026-01-01T00:00:00Z",
            "action": "upload via rclone",
            "process_name": "rclone.exe",
            "url": "https://storage.example/upload",
        },
        {
            "row_index": 2,
            "timestamp": "2026-01-01T00:01:00Z",
            "process_name": "psexec.exe",
            "dest_host": "dc01",
        },
    ]

    assessment_worker._seed_proposed_actions_and_kill_chain(assessment, clusters, rows)

    phases = [item["phase"] for item in assessment["kill_chain"]]
    assert "exfiltration" in phases
    assert "lateral_movement" in phases


def test_hopgraph_event_normalizer_maps_aliases_and_iso_timestamp():
    event = assessment_worker._hopgraph_event_from_row(
        {
            "source_ip": "10.0.0.5",
            "destination_ip": "203.0.113.10",
            "process_name": "rclone.exe",
            "hostname": "host-1",
            "url": "https://storage.example/upload",
            "timestamp": "2026-01-01T00:00:00Z",
            "sha256": "abc123",
        }
    )

    assert event["src_ip"] == "10.0.0.5"
    assert event["dst_ip"] == "203.0.113.10"
    assert event["process"] == "rclone.exe"
    assert event["src_host"] == "host-1"
    assert event["domain"] == "storage.example"
    assert event["file_hash"] == "abc123"
    assert isinstance(event["timestamp"], float)
