import asyncio

import pytest

from core.hunt.evidence_envelope import EvidenceEnvelope
from core.hunt.lanes.process_lineage import build


@pytest.mark.asyncio
async def test_office_macro_powershell_and_encoded():
    lane = build()
    event = {
        'id':'e1',
        'process_name':'powershell.exe',
        'parent_process_name':'winword.exe',
        'cmdline':'powershell.exe -enc QUJDREVGRw=='
    }
    env = EvidenceEnvelope(event)
    await lane.run(env, type('Ctx', (), {'elapsed_ms': lambda self: 0.1})())
    factors = env.all_factors
    assert any('office_macro_spawn_powershell' in f for f in factors)
    assert any('powershell_encoded_command' in f for f in factors)

@pytest.mark.asyncio
async def test_signed_to_unsigned_transition():
    lane = build()
    event = {
        'id':'e2',
        'process_name':'child.exe',
        'parent_process_name':'parent.exe',
        'process_signed': False,
        'parent_process_signed': True
    }
    env = EvidenceEnvelope(event)
    await lane.run(env, type('Ctx', (), {'elapsed_ms': lambda self: 0.1})())
    factors = env.all_factors
    assert any('signed_to_unsigned_transition' in f for f in factors)
