import asyncio
import json

from src.api import deep_analyze_endpoints as dae
from src.correlation.canonical_event import CanonicalEvent
from src.correlation.factors.factors_network import extract_network_factors


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
