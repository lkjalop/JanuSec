import time

import pytest

from src.core.correlation.factor_constants import (
    CORR_ANOMALOUS_USER_AGENT_CHAIN,
    CORR_C2_MULTI_CHANNEL,
    CORR_DNS_FAST_FLUX_LIKE,
    CORR_DNS_TUNNEL_THROUGHPUT,
    CORR_EGRESS_EXFIL_PATTERN,
    CORR_EXFIL_VIA_DNS,
    CORR_PERSISTENT_BEACON_CLUSTER,
    CORR_PHISH_MACRO_OUTBOUND_C2,
    CORR_PORT_SWEEP_PROBABLE,
    CORR_RANSOMWARE_BEACON_CHAIN,
    CORR_SSH_BRUTE_HIGH_FAIL,
    CORR_STEALTH_LATERAL_STAGING,
    CORR_TUNNEL_EXFIL_COMBO,
    JA3_RARE,
    OFFICE_MACRO_SPAWN_POWERSHELL,
    POWERSHELL_ENCODED_COMMAND,
    PROC_PARENT_CHAIN,
)
from src.core.correlation.hunt_correlation import create_correlation_engine, get_correlation_engine


class DummyConfig(dict):
    pass


def make_event(host):
    return {'host': host}


@pytest.mark.parametrize("factors,expected", [
    (['dns:tunnel_suspected','net:beacon_periodic'], {CORR_C2_MULTI_CHANNEL}),
    (['dns:tunnel_suspected','net:egress_port_scatter'], {CORR_DNS_TUNNEL_THROUGHPUT, CORR_TUNNEL_EXFIL_COMBO} if 'CORR_TUNNEL_EXFIL_COMBO' in globals() else {CORR_DNS_TUNNEL_THROUGHPUT}),
])
def test_c2_and_tunnel_rules(factors, expected):
    eng = create_correlation_engine(DummyConfig())
    ev = make_event('host1')
    import asyncio
    loop_result = asyncio.get_event_loop().run_until_complete(eng.correlate(factors, event=ev))
    assert expected.intersection(set(loop_result))


def test_port_sweep_and_conn_rate_combination():
    eng = get_correlation_engine(DummyConfig(), force_new=True)
    ev = make_event('host2')
    import asyncio
    res = asyncio.get_event_loop().run_until_complete(eng.correlate(['net:egress_port_scatter','conn_rate_anomaly'], event=ev))
    assert CORR_PORT_SWEEP_PROBABLE in res or CORR_EGRESS_EXFIL_PATTERN in res


def test_temporal_seen_within_behavior():
    eng = create_correlation_engine(DummyConfig())
    host = 'temp-host'
    import asyncio
    # First event marks beacon_like
    r1 = asyncio.get_event_loop().run_until_complete(eng.correlate(['net:beacon_periodic'], event=make_event(host)))
    # Immediately send dns tunneling, should correlate across temporal window
    r2 = asyncio.get_event_loop().run_until_complete(eng.correlate(['dns:tunnel_suspected'], event=make_event(host)))
    # we expect C2 multi-channel to appear because net:beacon_periodic was recently seen
    assert CORR_C2_MULTI_CHANNEL in r2


def test_office_macro_and_domain_novelty_phish_macro():
    eng = get_correlation_engine(DummyConfig(), force_new=True)
    ev = make_event('host-phish')
    import asyncio
    res = asyncio.get_event_loop().run_until_complete(eng.correlate([OFFICE_MACRO_SPAWN_POWERSHELL,'domain_novel_observed'], event=ev))
    # Ensure the phish macro outbound C2 correlation is emitted
    assert CORR_PHISH_MACRO_OUTBOUND_C2 in res
