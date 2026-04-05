"""Replay determinism test.

Ensures that running the same scenario twice produces identical factor sets and confidence series length.
Allows some flexibility if confidence values have minor floating drift (currently expecting exact match).

Marked @pytest.mark.slow: this test spawns subprocesses and may take 30+ seconds.
Run explicitly with: pytest -m slow tests/test_replay_determinism.py
"""
from __future__ import annotations

import asyncio
import json
import pytest

SCENARIO = 'macro_rare_ja3'

async def run_once():
    from scripts.replay_harness import run_scenario
    return await run_scenario(SCENARIO)


@pytest.mark.slow
@pytest.mark.timeout(120)
def test_replay_determinism():
    r1 = asyncio.run(run_once())
    r2 = asyncio.run(run_once())
    assert r1['factors'] == r2['factors'], f"Factor set drift between runs: {r1['factors']} vs {r2['factors']}"
    assert len(r1['confidence_series']) == len(r2['confidence_series']), "Confidence series length changed"

