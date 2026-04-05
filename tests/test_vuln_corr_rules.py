import pytest

from core.correlation.hunt_correlation import create_correlation_engine


class DummyCfg(dict):
    pass


@pytest.mark.asyncio
async def test_corr_vuln_host_egress_spike():
    eng = create_correlation_engine(DummyCfg())
    new = await eng.correlate(['vuln:cvss_ge_9', 'egress_volume_spike'], event={'src_ip': '10.0.0.5'})
    assert 'corr:vuln_host_egress_spike' in new


@pytest.mark.asyncio
async def test_corr_vuln_host_beacon():
    eng = create_correlation_engine(DummyCfg())
    new = await eng.correlate(['vuln:cvss_ge_9', 'net:beacon_periodic'], event={'src_ip': '10.0.0.6'})
    assert 'corr:vuln_host_beacon' in new


@pytest.mark.asyncio
async def test_corr_lolbin_on_vuln_asset():
    eng = create_correlation_engine(DummyCfg())
    new = await eng.correlate(['vuln:cvss_ge_9', 'endpoint:lolbin_cmd_tfidf_rare'], event={'src_ip': '10.0.0.7'})
    assert 'corr:lolbin_on_vuln_asset' in new

