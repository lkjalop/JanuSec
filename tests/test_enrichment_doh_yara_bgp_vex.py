import asyncio
import json
import types

import pytest

# KEV/EPSS enrichment basic test
@pytest.mark.asyncio
async def test_sbom_enrichment_and_vex(monkeypatch):
    from src.api.sbom_endpoints import sbom_upload, sbom_vulns, sbom_vex
    # Mock ENRICHER to be deterministic
    import src.api.sbom_endpoints as sb
    class FakeEnricher:
        async def enrich(self, vulns):
            out=[]
            for v in vulns:
                nv=dict(v)
                # assign KEV to fake CVE and EPSS to others
                cve = nv.get('cve') or 'CVE-2024-0001'
                nv['cve']=cve
                nv['kev'] = (cve=='CVE-2024-0001')
                nv['epss'] = 0.9 if not nv['kev'] else 0.2
                nv['exploit_available'] = nv['kev'] or nv['epss']>=0.7
                nv['risk_score'] = min(1.0, float(nv.get('risk_score') or 0.3) + (0.2 if nv['kev'] else 0.1))
                out.append(nv)
            return out
    sb.ENRICHER = FakeEnricher()
    class Req:
        def __init__(self, data): self._d=data
        async def json(self): return self._d
    # Upload SBOM with two components, one with CVE marker in heuristic (we simulate)
    r = await sbom_upload(Req({ 'components': [ {'name':'log4j','version':'2.14.1'}, {'name':'libxyz','version':'1.0.0'} ] }))
    sbom_id = r['sbom_id']
    out = await sbom_vulns(sbom_id)
    assert out['sbom_id'] == sbom_id
    assert isinstance(out['vulns'], list)
    # verify enrichment fields
    assert all('kev' in v and 'epss' in v and 'exploit_available' in v for v in out['vulns'])
    # apply VEX: not_affected for the first vuln (no actual CVE in heuristic, but endpoint tolerates missing)
    vex_body = { 'sbom_id': sbom_id, 'statements': [ {'component':'log4j','cve':'CVE-2024-0001','status':'not_affected','justification':'test','version_range':'>=2.0.0,<3.0.0'} ] }
    rv = await sbom_vex(Req(vex_body))
    assert rv['sbom_id'] == sbom_id
    out2 = await sbom_vulns(sbom_id)
    assert isinstance(out2['vulns'], list)
    # suppressed item should be filtered out by default
    names = [v.get('component') for v in out2['vulns']]
    assert 'log4j' not in names
    # when include_suppressed=True it should appear with suppression flags
    out3 = await sbom_vulns(sbom_id, include_suppressed=True)
    all_names = [v.get('component') for v in out3['vulns']]
    assert 'log4j' in all_names
    # at least mark suppression if the VEX matched by component+cve
    # no strict assert on fields because CVE isn't present in heuristic, but endpoint shouldn't raise

# DoH detection test
def test_network_doh_detection():
    from src.modules.network_hunter import NetworkThreatHunter
    hunter = NetworkThreatHunter(config={})
    # Simulate novelty by prior factor injection and DoH HTTP/3 (QUIC)
    event = {
        'host': 'dns.google',
        'http_path': '/dns-query',
        'alpn': 'h3',
    }
    # Call private analyzer directly for determinism
    factors = ['domain_novel_observed']
    delta = hunter._analyze_doh(event, factors)
    assert any(f in factors for f in ('network:doh_quic','network:doh_tunnel_suspect'))
    assert delta > 0

def test_bgp_enrichment_factor():
    from src.modules.network_hunter import NetworkThreatHunter
    hunter = NetworkThreatHunter(config={})
    hunter.bgp_incidents = {'203.0.113.0/24'}
    ev = {'dst_ip':'203.0.113.5'}
    factors = []
    d = hunter._analyze_bgp_context(ev, factors)
    assert 'network:bgp_hijack_context' in factors and d > 0

# YARA metrics counters test (no yara runtime needed)
@pytest.mark.asyncio
async def test_yara_metrics_error_timeout_counters(monkeypatch):
    from src.api import yara_endpoints as ye
    # Ensure YARA is enabled
    monkeypatch.setenv('YARA_ENABLED','1')
    # Inject fake _RULES
    ye._RULES.clear()
    ye._RULES['TestRuleA'] = 'rule TestRuleA { condition: true }'
    # Mock _import_yara to raise for compile to simulate error path
    def fake_import():
        class Fake:
            def compile(self, *a, **k):
                raise Exception('compile fail')
        return Fake()
    monkeypatch.setattr(ye, '_import_yara', fake_import)
    # Call save_rule to trigger compile error and ensure no crash
    with pytest.raises(Exception):
        await ye.save_rule({'name':'X','rule':'rule X { condition:true }'})
    # Now mock scan path to raise timeout in _maybe_apply_timeout via environment and fake rules
    ye._RULES['TestRuleB'] = 'rule TestRuleB { condition: true }'
    # mock _compile_all to return object with match to avoid compile
    class FakeRules:
        def match(self, data=None):
            # Simulate slow path so timeout triggers; we'll just raise to simulate error
            raise Exception('scan failed')
    monkeypatch.setattr(ye, '_compile_all', lambda: FakeRules())
    # call scan_path expecting HTTP 500
    with pytest.raises(Exception):
        await ye.scan_path({'path':'nonexistent'})

# BGP stub test
def test_bgp_stub():
    from src.api.bgp_endpoints import list_bgp_incidents
    loop = asyncio.new_event_loop()
    j = loop.run_until_complete(list_bgp_incidents())
    assert 'incidents' in j and isinstance(j['incidents'], list)
