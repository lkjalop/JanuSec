from __future__ import annotations

from src.integrations.bgp_client import BgpClient


def test_get_prefix_for_ip_simple():
    c = BgpClient()
    # inject prefixes manually
    c._prefixes = {'203.0.113.0/24', '203.0.113.0/25', '198.51.100.0/24'}
    assert c.get_prefix_for_ip('203.0.113.5') in {'203.0.113.0/25', '203.0.113.0/24'}
    assert c.get_prefix_for_ip('198.51.100.8') == '198.51.100.0/24'
    assert c.get_prefix_for_ip('192.0.2.1') is None
