import os, time
import pytest

from src.modules.network_hunter import NetworkThreatHunter

class DummyConfig: pass

@pytest.fixture
def hunter():
    return NetworkThreatHunter(DummyConfig())

def test_header_accept_rarity(monkeypatch, hunter):
    monkeypatch.setenv('ACCEPT_RARE_THRESHOLD','2')
    base_event = {'http_headers': {'host':'example.com','accept':'text/html','accept-language':'en-US'}}
    # First two occurrences should mark rare
    r1 = hunter._analyze_http_headers(base_event.copy(), [])
    factors = []
    hunter._analyze_http_headers(base_event.copy(), factors)
    assert 'http:accept_rare' in factors
    assert 'http:accept_language_rare' in factors
    # Third occurrence should not add new rare again (already counted)
    factors2 = []
    hunter._analyze_http_headers(base_event.copy(), factors2)
    # They may still appear but rarity threshold satisfied; ensure factors present remains stable
    assert 'http:accept_rare' in factors2


def test_host_mismatch_and_referer_external(hunter):
    factors = []
    evt = {'http_headers': {'host':'internal.local','referer':'http://evil.com/page','accept':'app/json','accept-language':'fr'}, 'host':'internal.real'}
    hunter._analyze_http_headers(evt, factors)
    assert 'http:host_mismatch' in factors
    assert 'http:referer_external_pivot' in factors


def test_portscan_vertical_and_horizontal(hunter):
    src = '10.0.0.5'
    dst_base = '10.0.1.'
    # Lower thresholds for test speed
    hunter.PORTSCAN_VERTICAL_THRESHOLD = 5
    hunter.PORTSCAN_HORIZONTAL_THRESHOLD = 5
    # Vertical: many distinct ports to same dst
    dst = dst_base + '10'
    ev_template = {'src_ip':src,'dst_ip':dst}
    for p in range(1,7):
        ev = ev_template | {'dst_port': 1000 + p}
        factors = []
        hunter._analyze_portscan(ev, factors)
    factors_v = []
    hunter._analyze_portscan({'src_ip':src,'dst_ip':dst,'dst_port':2000}, factors_v)
    assert 'net:possible_portscan_vertical' in factors_v
    # Horizontal: same port across many dst
    for i in range(1,7):
        factors_h = []
        hunter._analyze_portscan({'src_ip':src,'dst_ip': dst_base+str(20+i),'dst_port':443}, factors_h)
    factors_h2 = []
    hunter._analyze_portscan({'src_ip':src,'dst_ip': dst_base+'99','dst_port':443}, factors_h2)
    assert 'net:possible_portscan_horizontal' in factors_h2
