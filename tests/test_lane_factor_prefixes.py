"""Governance test: ensure all hunt lane emissions use required prefix pattern.

Rules:
 - All factors emitted by hunt lanes must start with 'lane_<lane_name>:' as enforced by envelope sanitization.
 - No raw (unprefixed) factors should leak.
"""
from __future__ import annotations

import asyncio
import re
from typing import List

PREFIX_PATTERN = re.compile(r"^lane_[a-z0-9_]+:\w")

async def collect_lane_factors(events):
    from main import SecurityOrchestrator
    orch = SecurityOrchestrator()
    await orch.initialize()
    try:
        orch.event_pipeline.config.setdefault('pipeline', {}).setdefault('hunt_lanes', {})['enabled'] = True  # type: ignore
    except Exception:
        pass
    factors: list[str] = []
    for ev in events:
        res = await orch.process_event(ev)
        factors.extend(res.factors)
    await orch.shutdown()
    return list(set(factors))

def test_lane_factor_prefixes():
    # Feed synthetic events intended to trigger lane emissions
    events = [
        {'id':'t1','process_name':'powershell.exe','parent_process_name':'winword.exe','cmdline':'powershell -enc AAAA'},
        *[{'id':f'j{i}','ja3_hash':f'h{i%3}'} for i in range(60)],  # warm baseline, triggers ja3 novelty/rare
    ]
    factors = asyncio.run(collect_lane_factors(events))
    lane_factors = [f for f in factors if f.startswith('lane_')]
    assert lane_factors, "Expected at least one lane factor emission"
    # Ensure every lane-specific factor matches prefix pattern
    for f in lane_factors:
        assert PREFIX_PATTERN.match(f), f"Lane factor malformed: {f}"
    # Ensure no un-prefixed lane artifacts leaked
    leaks = [f for f in factors if not f.startswith('lane_') and any(x in f for x in ['powershell','ja3','macro'])]
    assert not leaks, f"Unprefixed lane-like factors leaked: {leaks}"
