from __future__ import annotations

import ast
from pathlib import Path

from src.core.ingest.threat_case_builder import build_threat_cases


ROOT = Path(__file__).resolve().parents[1]
ENRICHMENT_WORKBOOK = ROOT / "dump" / "test files" / "janusec_enrichment_context_v1.xlsx"


def test_enrichment_workbook_as_input_is_rejected_or_quarantined():
    from src.core.ingest.file_parser import parse_file
    from src.core.ingest.input_classifier import classify_xlsx_path

    verdict = classify_xlsx_path(ENRICHMENT_WORKBOOK, filename=ENRICHMENT_WORKBOOK.name)

    assert verdict["lane"] == "evaluation_answer_key"
    assert verdict["evidence_allowed"] is False

    rows = list(parse_file(str(ENRICHMENT_WORKBOOK), filename=ENRICHMENT_WORKBOOK.name))
    assert rows == []


def test_production_analysis_does_not_import_evaluation_or_fixtures():
    production_files = [
        ROOT / "src" / "api" / "deep_analyze_endpoints.py",
        ROOT / "src" / "core" / "ingest" / "assessment_worker.py",
        ROOT / "src" / "core" / "ingest" / "threat_case_builder.py",
        ROOT / "src" / "core" / "tier1_prefill" / "prefill_engine.py",
        ROOT / "src" / "prompts" / "tier1_cluster_prefill.py",
    ]
    banned_roots = ("tests", "fixtures", "dump", "evaluation")
    violations: list[str] = []

    for path in production_files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            for name in names:
                first = name.split(".", 1)[0]
                if first in banned_roots or any(part in banned_roots for part in name.split(".")):
                    violations.append(f"{path.relative_to(ROOT)} imports {name}")

    assert not violations


def test_no_scenario_answer_key_tokens_in_production_analysis_code():
    production_files = [
        ROOT / "src" / "api" / "deep_analyze_endpoints.py",
        ROOT / "src" / "core" / "ingest" / "cluster_narrator.py",
        ROOT / "frontend" / "static" / "js" / "breach.js",
        ROOT / "frontend" / "static" / "js" / "breach_cluster_tab.js",
    ]
    banned_tokens = [
        "santos",
        "backblaze",
        "snowflake",
        "sfl_data",
        "finance_wh",
        "fs01",
        "it-scripts",
        "rachel.nakamura",
        "marcus.delacroix",
        "aaron.blackwood",
        "red herring",
        "abdul mohammadi",
        "jacob richards",
        "minecraft",
    ]
    violations: list[str] = []
    for path in production_files:
        text = path.read_text(encoding="utf-8", errors="replace").lower()
        for token in banned_tokens:
            if token in text:
                violations.append(f"{path.relative_to(ROOT)} contains {token}")

    assert not violations


def test_threat_case_builder_preserves_raw_cluster_inventory():
    clusters = [
        {"cluster_id": "rclone-exfil", "row_refs": [1], "lead_description": "rclone data exfil to external storage"},
        {"cluster_id": "lsass-theft", "row_refs": [2], "lead_description": "lsass credential dumping"},
        {"cluster_id": "k8s-escape", "row_refs": [3], "lead_description": "privilege escalation launch privileged container"},
        {"cluster_id": "dns-beacon", "row_refs": [4], "lead_description": "low reputation DNS beaconing"},
        {"cluster_id": "travel-benign", "row_refs": [5], "lead_description": "approved travel sign-in"},
    ]
    rows = [
        {"row_index": 1, "description": "rclone data exfil to external storage", "triage_score": 0.9},
        {"row_index": 2, "description": "lsass credential dumping", "triage_score": 0.88},
        {"row_index": 3, "description": "privilege escalation launch privileged container", "triage_score": 0.8},
        {"row_index": 4, "description": "low reputation DNS beaconing", "triage_score": 0.75},
        {"row_index": 5, "description": "approved travel sign-in", "triage_score": 0.2},
    ]

    result = build_threat_cases(clusters, rows)

    assert "raw_correlation_clusters" in result
    assert "analysis_clusters" in result
    assert "threat_cases" in result
    assert len(result["raw_correlation_clusters"]) == 5
    assert len(result["analysis_clusters"]) >= 5
    assert len(result["threat_cases"]) >= 2
    assert all(c.get("confidence_calibration") == "uncalibrated" for c in result["analysis_clusters"])


def test_typed_campaign_does_not_promote_likely_verdict_to_validated_breach():
    clusters = [{
        "cluster_id": "candidate-rdp",
        "cluster_kind": "campaign",
        "verdict": "LIKELY_COMPROMISE",
        "final_verdict": "LIKELY_COMPROMISE",
        "confidence": 0.66,
        "phases": [{"phase_id": "bastion_rdp_lateral", "case_role": "lateral_movement"}],
        "entity_roles": [{"entity": "alex", "role": "actor", "status": "observed"}],
        "row_refs": [1],
    }]
    cases = build_threat_cases(clusters, [{"row_index": 1}])["threat_cases"]
    assert cases[0]["final_verdict"] == "SUSPECTED_BREACH"
    assert cases[0]["incident_name"] != "CONFIRMED INTRUSION"
    assert cases[0]["entity_roles"][0]["entity"] == "alex"


def test_kerberoast_target_account_is_supporting_evidence_not_actor_case():
    primary = {
        "cluster_id": "primary", "cluster_kind": "campaign", "verdict": "VALIDATED_BREACH",
        "phases": [{"phase_id": "kerberoasting", "case_role": "credential_access"}],
        "shared_users": ["martin"], "row_refs": [1],
        "entity_roles": [{"entity": "martin", "role": "actor", "basis": "event_principal"}],
    }
    target = {
        "cluster_id": "roast-target", "cluster_kind": "campaign", "verdict": "VALIDATED_BREACH",
        "phases": [{"phase_id": "kerberoasting", "case_role": "credential_access"}],
        "shared_users": ["svc_sql"], "row_refs": [2],
        "entity_roles": [
            {"entity": "svc_sql", "role": "actor", "basis": "event_principal"},
            {"entity": "svc_sql", "role": "target", "basis": "target_account"},
        ],
    }
    cases = build_threat_cases(
        [primary, target],
        [{"row_index": 1, "src_ip": "10.0.0.9"}, {"row_index": 2, "client_address": "10.0.0.9"}],
    )["threat_cases"]
    assert [case["case_id"] for case in cases] == ["primary"]
    assert "roast-target" in cases[0]["supporting_cluster_ids"]
    assert any(role["entity"] == "svc_sql" and role["role"] == "target" for role in cases[0]["entity_roles"])


def test_kerberoast_target_attaches_by_observed_source_to_ticket_forgery_campaign():
    primary = {
        "cluster_id": "primary", "cluster_kind": "campaign", "verdict": "VALIDATED_BREACH",
        "phases": [{"phase_id": "kerberos_ticket_forgery", "case_role": "persistence"}],
        "shared_users": ["alex"], "shared_ips": ["10.0.0.9"], "row_refs": [1],
        "entity_roles": [{"entity": "alex", "role": "actor", "basis": "event_principal"}],
    }
    target = {
        "cluster_id": "roast-target", "cluster_kind": "campaign", "verdict": "VALIDATED_BREACH",
        "phases": [{"phase_id": "kerberoasting", "case_role": "credential_access"}],
        "shared_users": ["svc_sql"], "shared_ips": ["10.0.0.9"], "row_refs": [2],
        "entity_roles": [{"entity": "svc_sql", "role": "target", "basis": "target_account"}],
    }
    cases = build_threat_cases(
        [primary, target],
        [{"row_index": 1, "src_ip": "10.0.0.9"}, {"row_index": 2, "client_address": "10.0.0.9"}],
    )["threat_cases"]
    assert [case["case_id"] for case in cases] == ["primary"]
    assert "roast-target" in cases[0]["supporting_cluster_ids"]
    assert "kerberoasting" in {phase["phase_id"] for phase in cases[0]["phases"]}
