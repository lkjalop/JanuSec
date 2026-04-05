import asyncio

import pytest

from core.correlation.hunt_correlation import create_correlation_engine


class DummyConfig(dict):
    pass


@pytest.mark.asyncio
async def test_known_bad_ssl_encoded_ps():
    cfg = DummyConfig()
    eng = create_correlation_engine(cfg)
    new = await eng.correlate(['ssl:ja3_known_bad', 'lane_process_lineage:powershell_encoded_command'], event={'src_ip':'5.6.7.8'})
    assert 'corr_known_bad_ssl_encoded_ps' in new


@pytest.mark.asyncio
async def test_egress_exfil_pattern():
    cfg = DummyConfig()
    eng = create_correlation_engine(cfg)
    new = await eng.correlate(['net:egress_port_scatter', 'conn_rate_anomaly'], event={'src_ip':'9.9.9.9'})
    assert 'corr_egress_exfil_pattern' in new


@pytest.mark.asyncio
async def test_host_cache_gauge_updated():
    cfg = DummyConfig()
    eng = create_correlation_engine(cfg)
    # emit a factor for a host and ensure host cache contains the host
    await eng.correlate(['dns:tunnel_suspected'], event={'src_ip':'2.2.2.2'})
    assert '2.2.2.2' in eng.host_last_factor
