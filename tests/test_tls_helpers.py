import os
import sys
from pathlib import Path
import importlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.parsers.tls_helpers import parse_tls_client_hello


def test_parse_tls_client_hello_smoke():
    # Minimal synthetic TLS ClientHello byte sequence (not full spec but should be tolerated)
    # This is a compact handshake record with placeholder values. The parser should
    # not crash and should return tuple (sni, ja3_md5, ja4_md5) or (None, None, None).
    payload = b"\x16\x03\x01\x00\x30" + b"\x01\x00\x00\x2c" + b"\x03\x03" + b"\x00"*32 + b"\x00" + b"\x00\x02\x00\x2f" + b"\x01\x00\x00\x00"
    sni, ja3, ja4 = parse_tls_client_hello(payload)
    assert isinstance(sni, (str, type(None)))
    assert isinstance(ja3, (str, type(None)))
    assert isinstance(ja4, (str, type(None)))
    if ja3:
        assert len(ja3) == 32
