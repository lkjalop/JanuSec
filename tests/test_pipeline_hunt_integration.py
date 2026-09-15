import asyncio

import pytest

from main import SecurityOrchestrator


@pytest.mark.asyncio
async def test_pipeline_with_hunt_lanes_enabled():
    orch = SecurityOrchestrator()
    await orch.initialize()
    # Ensure lanes enabled
    orch.event_pipeline.config.setdefault('pipeline', {}).setdefault('hunt_lanes', {})['enabled'] = True  # type: ignore
    ev = {'id':'hunt1','process_name':'powershell.exe','parent_process_name':'winword.exe','cmdline':'powershell.exe -enc AAAA'}
    res = await orch.process_event(ev)
    await orch.shutdown()
    # Expect lane factors present
    assert any(f.startswith('lane_process_lineage:') for f in res.factors)

@pytest.mark.asyncio
async def test_pipeline_hunt_lanes_disabled():
    orch = SecurityOrchestrator()
    await orch.initialize()
    orch.event_pipeline.config.setdefault('pipeline', {}).setdefault('hunt_lanes', {})['enabled'] = False  # type: ignore
    ev = {'id':'hunt2','process_name':'powershell.exe','parent_process_name':'winword.exe','cmdline':'powershell.exe -enc AAAA'}
    res = await orch.process_event(ev)
    await orch.shutdown()
    assert not any(f.startswith('lane_') for f in res.factors)
