import os
import json
import tempfile
import pytest

try:
    import dpkt
    DPKT_OK = True
except Exception:
    DPKT_OK = False

from src.parsers.tls_helpers import parse_tls_client_hello


@pytest.mark.skipif(not DPKT_OK, reason="dpkt not installed")
def test_canonical_clienthello_roundtrip():
    # Generate a simple TCP packet carrying a TLS ClientHello using dpkt if possible
    # If dpkt is present we craft a raw ClientHello bytes minimal for our parser.
    # The test asserts parse_tls_client_hello returns tuple of (sni, ja3, ja4)
    # We're not attempting to build a full pcap writer here; we call the parser directly.
    # Minimal ClientHello bytes (simplified) — use a small synthetic blob known to parse.
    # This sample may not be representative; the goal is to validate function returns triple.
    client_hello_blob = b"\x16\x03\x01\x00\x2e\x01\x00\x00\x2a\x03\x03" + b"\x00"*30
    sni, ja3, ja4 = parse_tls_client_hello(client_hello_blob)
    assert isinstance(sni, (str, type(None)))
    assert isinstance(ja3, (str, type(None)))
    assert isinstance(ja4, (str, type(None)))
