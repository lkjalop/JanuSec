import asyncio

import pytest

from scripts import replay_harness


@pytest.mark.asyncio
async def test_replay_harness_lateral():
    result = await replay_harness.run_scenario('lateral_movement')
    assert 'graph_user_proc_burst' in result['factors']
    assert 'lateral_movement_candidate' in result['factors']

@pytest.mark.asyncio
async def test_replay_harness_exfiltration():
    result = await replay_harness.run_scenario('exfiltration')
    assert 'exfil_volume_high' in result['factors']

@pytest.mark.asyncio
async def test_replay_harness_dns_beacon():
    result = await replay_harness.run_scenario('dns_beacon')
    assert any(f.startswith('beacon_') for f in result['factors']) or 'beacon_like_30s' in result['factors']
    assert 'dns_tunnel_pattern' in result['factors']

@pytest.mark.asyncio
async def test_replay_harness_brute_force():
    result = await replay_harness.run_scenario('brute_force')
    assert 'auth_fail_burst_5m' in result['factors']
