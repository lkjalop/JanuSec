import asyncio

import pytest

from main import SecurityOrchestrator


@pytest.mark.asyncio
async def test_correlation_disabled_no_synergy_factor():
    orch = SecurityOrchestrator()
    await orch.initialize()
    # Disable correlation & enable hunt lanes using config mutation helper
    cfg = orch.event_pipeline.config
    if hasattr(cfg, 'set_flag'):
        cfg.set_flag('pipeline.correlation.enabled', False)
        cfg.set_flag('pipeline.hunt_lanes.enabled', True)
    else:  # fallback for legacy interface
        try:
            cfg.set_pipeline_flag('correlation','enabled', False)  # type: ignore
            cfg.set_pipeline_flag('hunt_lanes','enabled', True)    # type: ignore
        except Exception:
            pass
    # Provide factors by running event sim (some lane factors may appear); synergy requires correlation stage but is disabled
    ev = {'id':'corr0','process_name':'powershell.exe','parent_process_name':'winword.exe','cmdline':'powershell.exe -enc AAAA','ja3_hash':'rareX'}
    res = await orch.process_event(ev)
    await orch.shutdown()
    assert not any(f.startswith('corr_') for f in res.factors)
