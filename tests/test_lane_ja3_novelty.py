import asyncio

import pytest

from core.hunt.evidence_envelope import EvidenceEnvelope
from core.hunt.lanes.ja3_novelty import JA3NoveltyLane


class DummyConfig(dict):
    pass

@pytest.mark.asyncio
async def test_ja3_novel_and_rare_with_warm_min_1():
    cfg = DummyConfig()
    cfg['pipeline'] = {'hunt_lanes': {'ja3': {'warm_min': 1, 'rare_threshold': 2}}}
    lane = JA3NoveltyLane(cfg)
    env1 = EvidenceEnvelope({'id':'j1','ja3_hash':'abc'})
    await lane.run(env1, type('Ctx', (), {'elapsed_ms': lambda self: 0.1})())
    f1 = env1.all_factors
    assert any('ja3_novel' in f for f in f1)
    assert any('ja3_rare' in f for f in f1)
    env2 = EvidenceEnvelope({'id':'j2','ja3_hash':'abc'})
    await lane.run(env2, type('Ctx', (), {'elapsed_ms': lambda self: 0.1})())
    f2 = env2.all_factors
    # second time still rare (count=2 <= threshold 2) but not novel
    assert not any('ja3_novel' in f for f in f2)
    assert any('ja3_rare' in f for f in f2)
