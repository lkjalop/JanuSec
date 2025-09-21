import pytest
from main import SecurityOrchestrator

# We'll patch audit_repo to capture hashes
chain_calls = []

async def fake_append(event_id, action, details, custody_hash, prev_hash):
    chain_calls.append((action, custody_hash, prev_hash))

async def fake_get_last_hash(event_id):
    # Return last custody hash if exists
    for call in reversed(chain_calls):
        return call[1]
    return None

@pytest.mark.asyncio
async def test_custody_hash_chain(monkeypatch):
    import repositories.audit_repo as audit_repo
    monkeypatch.setattr(audit_repo, 'append_audit', fake_append)
    monkeypatch.setattr(audit_repo, 'get_last_hash', fake_get_last_hash)

    orch = SecurityOrchestrator()
    await orch.initialize()
    orch.decision_engine.malicious_threshold = 0.0  # force malicious

    event1 = {'id': 'chain1', 'severity': 'high', 'details': {}, 'timestamp': '2025-09-21T00:00:00Z'}
    await orch.process_event(event1)
    assert len(chain_calls) >= 2  # decision + alert

    # Extract hashes
    first_decision_hash = chain_calls[0][1]
    second_action_prev = chain_calls[1][2]
    assert second_action_prev == first_decision_hash, 'Hash chain not preserved'
