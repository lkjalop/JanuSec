from __future__ import annotations

from pathlib import Path

from scripts.offline_replay_harness import _load_rows


def test_offline_replay_harness_loads_azure_and_aws_json_fixtures():
    azure_rows = _load_rows(Path("tests/fixtures/iam/azure_signin.json"))
    aws_rows = _load_rows(Path("tests/fixtures/iam/cloudtrail_event.json"))

    assert azure_rows and azure_rows[0]["source_file"] == "azure_signin.json"
    assert aws_rows and aws_rows[0]["source_file"] == "cloudtrail_event.json"
    assert azure_rows[0]["sheet"] == "azure_signin"
    assert aws_rows[0]["sheet"] == "cloudtrail_event"


def test_offline_replay_harness_loads_exported_cloud_fixture_pack():
    fixture_paths = [
        Path("tests/fixtures/cloud_exports/azure_entra_signin_export.json"),
        Path("tests/fixtures/cloud_exports/azure_entra_audit_export.json"),
        Path("tests/fixtures/cloud_exports/azure_defender_incidents_export.json"),
        Path("tests/fixtures/cloud_exports/azure_activity_log_export.json"),
        Path("tests/fixtures/cloud_exports/azure_nsg_flow_export.json"),
        Path("tests/fixtures/cloud_exports/azure_conditional_access_export.json"),
        Path("tests/fixtures/cloud_exports/azure_identity_protection_export.json"),
        Path("tests/fixtures/cloud_exports/azure_combined_attack_chain.json"),
        Path("tests/fixtures/cloud_exports/aws_cloudtrail_export.json"),
        Path("tests/fixtures/cloud_exports/aws_config_export.json"),
        Path("tests/fixtures/cloud_exports/aws_guardduty_export.json"),
        Path("tests/fixtures/cloud_exports/aws_securityhub_export.json"),
        Path("tests/fixtures/cloud_exports/aws_vpc_flow_export.json"),
        Path("tests/fixtures/cloud_exports/aws_combined_attack_chain.json"),
    ]
    rows = [_load_rows(path) for path in fixture_paths]
    assert all(batch for batch in rows)
    assert {batch[0]["source_file"] for batch in rows} == {path.name for path in fixture_paths}


def test_offline_replay_harness_loads_manifest_pack_directories():
    azure_rows = _load_rows(Path("tests/fixtures/export_packs/azure_realish_tenant"))
    aws_rows = _load_rows(Path("tests/fixtures/export_packs/aws_realish_tenant"))

    assert azure_rows and aws_rows
    assert all(row.get("export_pack") == "azure_realish_tenant" for row in azure_rows[:3])
    assert all(row.get("export_pack") == "aws_realish_tenant" for row in aws_rows[:3])
    assert any(row.get("export_source") == "conditional_access" for row in azure_rows)
    assert any(row.get("export_source") == "config" for row in aws_rows)
