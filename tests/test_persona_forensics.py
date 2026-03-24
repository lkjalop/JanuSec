from src.reporting.persona_views import generate_persona_view


def test_forensics_persona_view_contains_investigation_fields():
    report = {
        "report_id": "rpt-forensics-1",
        "tenant_id": "default",
        "raw_event": {
            "host": "wkstn-01",
            "process_name": "powershell.exe",
            "sha256": "a" * 64,
            "domain": "example.com",
            "src_ip": "10.0.0.10",
            "dst_ip": "8.8.8.8",
        },
        "attack_timeline": [{"event_type": "execution", "description": "PowerShell launched"}],
        "network_artifacts": [{"type": "dns", "value": "example.com"}],
        "verdict": {"final_verdict": "THREAT", "all_factors": []},
    }

    view = generate_persona_view(report, "forensics", disclosure_level=2, top_n=5)

    assert view["persona"] == "forensics"
    assert view["timeline"]
    assert "investigation_checklist" in view
    assert "artifacts_to_collect" in view
    assert "evidence_sources" in view
    assert view["chain_of_custody"]["report_id"] == "rpt-forensics-1"
