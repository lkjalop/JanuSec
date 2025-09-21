import asyncio
import pytest
from types import SimpleNamespace

from main import SecurityOrchestrator

class DummyRepoCalls:
    def __init__(self):
        self.events = 0
        self.decisions = 0
        self.alerts = 0
        self.audits = 0

calls = DummyRepoCalls()

# Monkey patch repository functions
async def fake_upsert_event(event):
    calls.events += 1

async def fake_upsert_decision(event_id, decision):
    calls.decisions += 1

async def fake_insert_alert(event_id, verdict, confidence, severity, factors, playbook_result):
    calls.alerts += 1

async def fake_append_audit(event_id, action, details, custody_hash, prev_hash):
    calls.audits += 1

@pytest.mark.asyncio
async def test_persistence_smoke(monkeypatch):
    import repositories.events_repo as events_repo
    import repositories.decisions_repo as decisions_repo
    import repositories.alerts_repo as alerts_repo
    import repositories.audit_repo as audit_repo

    monkeypatch.setattr(events_repo, 'upsert_event', fake_upsert_event)
    monkeypatch.setattr(decisions_repo, 'upsert_decision', fake_upsert_decision)
    monkeypatch.setattr(alerts_repo, 'insert_alert', fake_insert_alert)
    monkeypatch.setattr(audit_repo, 'append_audit', fake_append_audit)
    monkeypatch.setattr(audit_repo, 'get_last_hash', lambda event_id: None)

    orch = SecurityOrchestrator()
    await orch.initialize()

    # Malicious event path to trigger alert persistence
    event = {'id': 'e1', 'severity': 'high', 'details': {}, 'timestamp': '2025-09-21T00:00:00Z'}
    # Force pipeline result -> decision path by monkeypatching decision engine thresholds
    orch.decision_engine.malicious_threshold = 0.0  # everything malicious

    await orch.process_event(event)

    assert calls.events == 1, 'Event upsert not called'
    assert calls.decisions == 1, 'Decision upsert not called'
    assert calls.alerts == 1, 'Alert insert not called'
    assert calls.audits >= 2, 'Audit append not called for decision and alert'
