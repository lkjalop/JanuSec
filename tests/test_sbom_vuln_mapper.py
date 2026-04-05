from modules.sbom_vuln_mapper import SBOMVulnMapper
from repositories.sbom_vuln_agg_repo import record_vulnerability


def test_sbom_vuln_cap():
    mapper = SBOMVulnMapper(type('Cfg',(object,),{'get':lambda *_a,**_k:{'confidence_cap':0.1}})())
    tenant='t'; comp='compA:1.0'
    for _ in range(2):
        record_vulnerability(tenant, comp, 'critical')
    for _ in range(5):
        record_vulnerability(tenant, comp, 'high')
    for _ in range(30):
        record_vulnerability(tenant, comp, 'medium')
    res = mapper.map_event(tenant, comp, [])
    assert res['delta'] <= 0.1001
    assert 'sbom:cve_critical' in res['factors']
    assert 'sbom:cve_high_density' in res['factors']
