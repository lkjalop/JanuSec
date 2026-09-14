import pytest

from main import SecurityOrchestrator
from repositories import audit_repo


@pytest.mark.asyncio
async def test_custody_hash_chain():
    orch = SecurityOrchestrator()
    await orch.initialize()
    # Force malicious path so fast-path audit creates both entries
    orch.decision_engine.malicious_threshold = 0.0
    event = {'id': 'chain1', 'severity': 'high', 'details': {}, 'timestamp': '2025-09-21T00:00:00Z'}
    await orch.process_event(event)

    chain = audit_repo.get_inmem_chain('chain1')
    actions = [(c.get('action'), c.get('custody_hash'), c.get('prev_hash')) for c in chain]
    assert len(actions) >= 2, f"Expected >=2 audit records, got {len(actions)} from {actions}"
    # Find decision then alert
    decision = next((a for a in actions if a[0]=='decision_recorded'), None)
    alert = next((a for a in actions if a[0]=='alert_generated'), None)
    assert decision and alert, f"Missing decision or alert entries: {actions}"
    assert alert[2] == decision[1], f"Hash chain not preserved: alert.prev={alert[2]} decision.hash={decision[1]}"
