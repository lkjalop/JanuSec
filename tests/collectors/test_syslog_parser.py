import pytest
from syslog_rfc5424_parser import SyslogMessage


def test_rfc5424_parse_simple():
    line = "<34>1 2025-12-23T12:34:56.000Z myhost app - - - Example syslog message"
    msg = SyslogMessage.parse(line)
    # parser exposes timestamp, hostname and msg
    assert getattr(msg, "timestamp", None) is not None
    assert getattr(msg, "hostname", None) == "myhost"
    assert "Example syslog message" in (getattr(msg, "msg", "") or "")


def test_rfc3164_parser_basic():
    from src.collectors.rfc3164_parser import RFC3164Parser
    p = RFC3164Parser()
    line = "<34>Dec 23 12:34:56 myhost app[123]: A test message"
    parsed = p.parse_line(line)
    assert parsed.pri == 34
    assert parsed.hostname == "myhost"
    assert "test message" in (parsed.msg or "")


def test_cef_parse():
    from src.collectors.structured_parsers import parse_cef, is_cef
    line = "CEF:0|Acme|Product|1.0|100|Test Event|5|src=1.2.3.4 dst=5.6.7.8 msg=hello"
    assert is_cef(line)
    parsed = parse_cef(line)
    assert parsed.get("vendor") == "Acme"
    assert parsed.get("extension").get("src") == "1.2.3.4"


def test_rfc3164_to_canonical():
    from src.collectors.rfc3164_parser import RFC3164Parser
    p = RFC3164Parser()
    line = "<34>Dec 23 12:34:56 myhost app[123]: A test message"
    parsed = p.parse_line(line)
    canon = p.to_canonical(parsed)
    assert canon["message"] and "test message" in canon["message"]


def test_cef_canonical_mapping():
    from src.collectors.structured_parsers import parse_cef
    line = "CEF:0|Acme|Product|1.0|100|Test Event|5|src=1.2.3.4 dst=5.6.7.8 spt=123 dpt=456 rt=1700000000"
    parsed = parse_cef(line)
    canonical = parsed.get("canonical")
    assert canonical.get("src_ip") == "1.2.3.4"
    assert canonical.get("dst_ip") == "5.6.7.8"
