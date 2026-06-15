"""Firewall (CEF + FortiGate/Palo field maps) and MCP/AI-agent ingestion."""
from __future__ import annotations

from src.collectors.structured_parsers import parse_cef, is_cef
from src.pipeline.streaming_ingest import normalize_row, classify_source, SOURCE_NETWORK, SOURCE_ENDPOINT
from src.core.ingest.cluster_merge import detect_row_phase_tags, PHASE_DETECTORS
from src.core.mappings.factor_to_mitre import get_all_mappings
from src.core.ingest.cluster_narrator import _FACTOR_TAG_LABELS


_FORTI_CEF = ("CEF:0|Fortinet|FortiGate|7.4|ips|IPS Signature Detected|9|"
              "src=203.0.113.7 dst=10.0.0.5 spt=44321 dpt=443 act=blocked "
              "cat=intrusion suser=attacker dhost=web01")


def test_cef_parse_fixes_name_offset_and_extracts_threat_fields():
    assert is_cef(_FORTI_CEF)
    c = parse_cef(_FORTI_CEF)
    # name is the CEF Name (parts[5]), NOT severity (the old offset bug).
    assert c["name"] == "IPS Signature Detected"
    assert c["src_ip"] == "203.0.113.7"
    assert c["dst_ip"] == "10.0.0.5"
    assert c["action"] == "blocked"
    assert c["category"] == "intrusion"
    assert c["user"] == "attacker"
    assert c["severity"] == "critical"          # CEF sev 9 -> critical
    assert c["event_name"] == "IPS Signature Detected"
    assert "fortinet" in c["_source"]            # classifies downstream as NETWORK


def test_firewall_threat_detector_fires_and_clusters():
    c = parse_cef(_FORTI_CEF)
    r = normalize_row(c)
    assert r["_source_type"] == SOURCE_NETWORK
    r["row_index"] = 1
    assert "firewall_threat" in detect_row_phase_tags(r)


def test_fortigate_native_kv_field_map():
    assert classify_source("fortinet") == SOURCE_NETWORK
    row = {"_source": "fortinet", "srcip": "203.0.113.7", "dstip": "10.0.0.5",
           "action": "deny", "subtype": "ips", "attack": "Apache.Struts.RCE", "srccountry": "RU"}
    r = normalize_row(row)
    assert r["src_ip"] == "203.0.113.7" and r["dst_ip"] == "10.0.0.5"
    assert r["category"] == "ips" and r["event_name"] == "Apache.Struts.RCE"
    assert r["geo_country"] == "RU"
    r["row_index"] = 2
    assert "firewall_threat" in detect_row_phase_tags(r)


def test_mcp_tool_call_ingestion_and_abuse_detector():
    assert classify_source("mcp") == SOURCE_ENDPOINT
    row = {"_source": "mcp", "agent_id": "agent-7", "tool_name": "read_file",
           "mcp_server": "files-mcp", "request_id": "req-abc", "mcp_event": "tool_call",
           "scope_violation": True, "resource_uri": "/etc/shadow"}
    r = normalize_row(row)
    assert r["user"] == "agent-7"
    assert r["event_name"] == "read_file"
    assert r["session_id"] == "req-abc"        # request id -> identity-pivot session
    r["row_index"] = 3
    assert "mcp_tool_abuse" in detect_row_phase_tags(r)
    det = next(d for d in PHASE_DETECTORS if d.phase_id == "mcp_tool_abuse")
    assert det.case_role == "execution"


def test_firewall_mcp_factors_map_and_narrate():
    for factor, code in {"network:firewall_threat_block": "T1190",
                         "ai:mcp_tool_poisoning": "AML.T0051",
                         "ai:mcp_scope_violation": "AML.T0053"}.items():
        assert code in get_all_mappings([factor]).get("mitre", [])
        assert factor in _FACTOR_TAG_LABELS
