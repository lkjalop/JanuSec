import asyncio
import base64
import io
import json
import zipfile

from src.api import deep_analyze_endpoints as dae
from src.correlation.canonical_event import CanonicalEvent
from src.correlation.factors.factors_network import extract_network_factors
from src.core.detectors import bec_scoring_model as bec_model
from src.core.detectors import persistence_scoring_model as persistence_model


def test_network_ml_pipeline_factors_are_emitted_through_extract_network_factors():
    events = []
    for idx in range(6):
        events.append(
            CanonicalEvent.from_dict(
                {
                    "timestamp": 1710000000 + (idx * 30),
                    "tenant": "default",
                    "source_type": "network",
                    "src_ip": "10.0.0.5",
                    "dst_ip": "198.51.100.42",
                    "dst_port": 443,
                    "domain": "evil.example",
                    "dns_query": "ajsdqwoeiruzmxncvbqplkqweiru.example.com",
                    "ja3": "72a589da586844d7f0818ce684948eea",
                    "sni": "rare-c2.example",
                    "bytes_out": 80000,
                    "packets": 100,
                    "duration": 1.2,
                }
            )
        )

    factors = extract_network_factors(events)
    names = {str(item.get("name") or "") for item in factors}
    assert (
        "net:beacon_statistical" in names
        or "net:beacon_jitter_detected" in names
        or "beaconing_interval_regular" in names
    )
    assert "dns:tunnel_entropy_high" in names or "dns:tunnel_long_query" in names
    assert "ssl:ja3_sslbl_match" in names


def test_deep_analyze_can_merge_endpoint_email_ml_factors_into_rows(monkeypatch):
    monkeypatch.setenv("TEST_HELPERS_ENABLED", "1")
    payload = {
        "tenant": "default",
        "enable_endpoint_email_ml": True,
        "options": {"auto_llm": False, "enable_endpoint_email_ml": True},
        "rows": [
            {
                "row_index": 1,
                "source_type": "email",
                "source": "mimecast",
                "sender_domain": "shopsquire-payments.example",
                "headers": {
                    "from": "Chief Executive <ceo@shopsquire-payments.example>",
                    "reply-to": "wiredesk@evil-payments.example",
                    "to": "finance@shopsquire.example",
                    "subject": "URGENT transfer request",
                },
                "body": "URGENT: please process the transfer now and do not call anyone.",
                "attachment_name": "invoice.pdf.exe",
                "attachment_content": "TVqQAAMAAAAEAAAA",
                "mime": "application/octet-stream",
            },
            {
                "row_index": 2,
                "source_type": "endpoint",
                "source": "sysmon",
                "host": "WS-CEO-1",
                "hostname": "WS-CEO-1",
                "process_name": "cmd.exe",
                "process": "cmd.exe",
                "parent_process": "winword.exe",
                "parent": "winword.exe",
                "cmdline": "cmd.exe /c powershell -enc SQBFAFgA",
            },
        ],
        "email_messages": [
            {
                "filename": "invoice.pdf.exe",
                "content": "TVqQAAMAAAAEAAAA",
                "mime": "application/octet-stream",
                "sender_domain": "shopsquire-payments.example",
            }
        ],
    }

    response = asyncio.run(dae.run_deep_analyze_pipeline(payload))
    body = json.loads(response.body)
    ml_pipeline = body.get("ml_pipeline") or {}

    assert ml_pipeline.get("enabled") is True
    assert ml_pipeline.get("status") == "ok"
    factor_names = set(ml_pipeline.get("factor_names") or [])
    assert "email:bec_replyto_mismatch" in factor_names
    assert "email:attachment_double_ext" in factor_names
    assert "endpoint:process_tree_anomaly" in factor_names or "endpoint:lolbin_child_unusual" in factor_names

    evidence_rows = body.get("evidence_rows") or []
    email_row = next(row for row in evidence_rows if str(row.get("source") or row.get("source_type") or "").lower() == "mimecast")
    endpoint_row = next(row for row in evidence_rows if str(row.get("source") or row.get("source_type") or "").lower() == "sysmon")
    assert "email:bec_replyto_mismatch" in (email_row.get("factors") or [])
    assert "email:attachment_double_ext" in (email_row.get("factors") or [])
    assert any(name.startswith("endpoint:") for name in (endpoint_row.get("factors") or []))


def _base64_macro_zip() -> str:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("xl/vbaProject.bin", b"Attribute VB_Name = \"Module1\"\nSub AutoOpen()\nMsgBox \"x\"\nEnd Sub")
    return base64.b64encode(buf.getvalue()).decode("ascii")


def test_bec_sender_anomaly_emits_on_hourly_spike():
    bec_model._COMM_GRAPH.clear()
    bec_model._SENDER_HOURLY_STATE.clear()
    if getattr(bec_model, "_BEC_EWMA", None) is not None:
        bec_model._BEC_EWMA.tenants.clear()

    # Warm a low baseline across several prior hours, then spike the current hour.
    for hour in range(4):
        bec_model.score_bec(
            [
                {
                    "source_platform": "email",
                    "type": "mail",
                    "timestamp": float(1710000000 + (hour * 3600)),
                    "headers": {
                        "from": "Accounts <alerts@vendor.example>",
                        "to": "finance@shopsquire.example",
                        "subject": "Monthly statement",
                    },
                    "body": "Routine monthly statement.",
                }
            ],
            tenant_id="bec-test",
        )

    spike_events = []
    for idx in range(6):
        spike_events.append(
            {
                "source_platform": "email",
                "type": "mail",
                "timestamp": float(1710000000 + (10 * 3600) + idx),
                "headers": {
                    "from": "Accounts <alerts@vendor.example>",
                    "to": "finance@shopsquire.example",
                    "subject": "Urgent invoice follow-up",
                },
                "body": "Urgent follow-up.",
            }
        )

    factors = bec_model.score_bec(spike_events, tenant_id="bec-test")
    names = {str(item.get("factor") or "") for item in factors}
    assert "email:bec_sender_anomaly" in names


def test_deep_analyze_endpoint_email_ml_detects_macro_process_persistence_and_advanced_signals(monkeypatch):
    monkeypatch.setenv("TEST_HELPERS_ENABLED", "1")
    persistence_model._HOST_PERS_TIMES.clear()
    persistence_model._KNOWN_PERSISTENCE.clear()
    macro_b64 = _base64_macro_zip()
    payload = {
        "tenant": "slice-b-tenant",
        "enable_endpoint_email_ml": True,
        "options": {"auto_llm": False, "enable_endpoint_email_ml": True},
        "rows": [
            {
                "row_index": 1,
                "source_type": "email",
                "source": "mimecast",
                "sender_domain": "vendor.example",
                "headers": {
                    "from": "Chief Financial Officer <payments@vendor.example>",
                    "reply-to": "wire@evil-payments.example",
                    "to": "finance@shopsquire.example",
                    "subject": "URGENT payment change required today",
                },
                "body": "Urgent payment change required today. Keep confidential and process ASAP.",
                "attachment_name": "invoice.xlsm",
                "attachment_content": macro_b64,
                "mime": "application/vnd.ms-excel.sheet.macroEnabled.12",
            },
            {
                "row_index": 2,
                "source_type": "endpoint",
                "source": "sysmon",
                "host": "WS-CEO-1",
                "hostname": "WS-CEO-1",
                "process_name": "cmd.exe",
                "process": "cmd.exe",
                "parent_process": "winword.exe",
                "parent": "winword.exe",
                "cmdline": "cmd.exe /c powershell -enc SQBFAFgA",
            },
            {
                "row_index": 3,
                "source_type": "endpoint",
                "source": "sysmon",
                "host": "WS-CEO-1",
                "hostname": "WS-CEO-1",
                "process_name": "reg.exe",
                "process": "reg.exe",
                "registry_key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
                "cmdline": "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d evil.exe",
            },
            {
                "row_index": 4,
                "source_type": "endpoint",
                "source": "sysmon",
                "host": "WS-CEO-1",
                "hostname": "WS-CEO-1",
                "process_name": "schtasks.exe",
                "process": "schtasks.exe",
                "cmdline": "schtasks.exe /create /sc minute /mo 5 /tn updater /tr evil.exe",
            },
            {
                "row_index": 5,
                "source_type": "endpoint",
                "source": "sysmon",
                "host": "WS-CEO-1",
                "hostname": "WS-CEO-1",
                "process_name": "sc.exe",
                "process": "sc.exe",
                "cmdline": "sc.exe create updater binPath= evil.exe",
            },
            {
                "row_index": 6,
                "source_type": "endpoint",
                "source": "sysmon",
                "host": "WS-CEO-1",
                "hostname": "WS-CEO-1",
                "process_name": "powershell.exe",
                "process": "powershell.exe",
                "cmdline": "NtUnmapViewOfSection ; wbadmin delete catalog ; bcdedit /set recoveryenabled no ; \\\\fileserver\\share \\\\backup\\share",
            },
        ],
        "email_messages": [
            {
                "filename": "invoice.xlsm",
                "content": macro_b64,
                "mime": "application/vnd.ms-excel.sheet.macroEnabled.12",
                "sender_domain": "vendor.example",
            }
        ],
    }

    response = asyncio.run(dae.run_deep_analyze_pipeline(payload))
    body = json.loads(response.body)
    ml_pipeline = body.get("ml_pipeline") or {}
    factor_names = set(ml_pipeline.get("factor_names") or [])

    assert "email:attachment_ole_macro" in factor_names
    assert "email:bec_replyto_mismatch" in factor_names
    assert "endpoint:process_tree_anomaly" in factor_names or "endpoint:lolbin_child_unusual" in factor_names
    assert "endpoint:persistence_reg_run" in factor_names
    assert "endpoint:persistence_task_new" in factor_names
    assert "endpoint:persistence_service_new" in factor_names
    assert "endpoint:persistence_burst" in factor_names
    assert "endpoint:fileless_process_hollow" in factor_names
    assert "endpoint:ransom_backup_catalog_del" in factor_names
    assert "endpoint:ransom_inhibit_recovery" in factor_names

    evidence_rows = body.get("evidence_rows") or []
    email_row = next(row for row in evidence_rows if str(row.get("source") or row.get("source_type") or "").lower() == "mimecast")
    assert "email:attachment_ole_macro" in (email_row.get("factors") or [])
    assert "email:bec_replyto_mismatch" in (email_row.get("factors") or [])

    endpoint_factors = set()
    for row in evidence_rows:
        if str(row.get("source") or row.get("source_type") or "").lower() == "sysmon":
            endpoint_factors.update(row.get("factors") or [])
    assert "endpoint:persistence_burst" in endpoint_factors
    assert "endpoint:fileless_process_hollow" in endpoint_factors
