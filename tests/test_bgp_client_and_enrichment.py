import asyncio
import pytest


def test_bgp_parse_variants():
    from src.integrations.bgp_client import BgpClient
    data1 = { 'incidents': [ {'prefix':'198.51.100.0/24'}, {'cidr':'2001:db8::/32'}, '203.0.113.0/24' ] }
    s = BgpClient.parse_feed(data1)
    assert '198.51.100.0/24' in s and '203.0.113.0/24' in s and '2001:db8::/32' in s
    data2 = [ '192.0.2.0/24', {'prefix':'10.0.0.0/8'} ]
    s2 = BgpClient.parse_feed(data2)
    assert '192.0.2.0/24' in s2 and '10.0.0.0/8' in s2


def test_hunter_bgp_enrichment_with_overlaps():
    from src.modules.network_hunter import NetworkThreatHunter
    h = NetworkThreatHunter(config={})
    # overlapping prefixes: /24 and /25
    h.bgp_incidents = {'203.0.113.0/24', '203.0.113.0/25'}
    factors = []
    d = h._analyze_bgp_context({'dst_ip':'203.0.113.7'}, factors)
    assert 'network:bgp_hijack_context' in factors and d > 0
