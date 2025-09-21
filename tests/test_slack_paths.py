import pytest
from main import SecurityOrchestrator

class SlackMock:
    def __init__(self, succeed=True):
        self.succeed = succeed
        self.calls = 0
    async def send_alert(self, severity: str, text: str, blocks=None):
        self.calls += 1
        return self.succeed

@pytest.mark.asyncio
async def test_slack_disabled(monkeypatch):
    orch = SecurityOrchestrator()
    await orch.initialize()
    # Force malicious
    orch.decision_engine.malicious_threshold = 0.0
    # Ensure slack_notifier remains None
    orch.slack_notifier = None
    event = {'id': 'e_slack0', 'severity': 'high', 'details': {}, 'timestamp': '2025-09-21T00:00:00Z'}
    await orch.process_event(event)
    # No error means path okay; nothing to assert besides absence
    assert orch.slack_notifier is None

@pytest.mark.asyncio
async def test_slack_enabled_success(monkeypatch):
    orch = SecurityOrchestrator()
    await orch.initialize()
    orch.decision_engine.malicious_threshold = 0.0
    mock = SlackMock(succeed=True)
    orch.slack_notifier = mock
    event = {'id': 'e_slack1', 'severity': 'high', 'details': {}, 'timestamp': '2025-09-21T00:00:00Z'}
    await orch.process_event(event)
    assert mock.calls == 1
    # slack_failures_total should remain 0
    assert orch.metrics.counters['slack_failures_total'] == 0

@pytest.mark.asyncio
async def test_slack_enabled_failure(monkeypatch):
    orch = SecurityOrchestrator()
    await orch.initialize()
    orch.decision_engine.malicious_threshold = 0.0
    mock = SlackMock(succeed=False)
    orch.slack_notifier = mock
    event = {'id': 'e_slack2', 'severity': 'high', 'details': {}, 'timestamp': '2025-09-21T00:00:00Z'}
    await orch.process_event(event)
    assert mock.calls == 1
    assert orch.metrics.counters['slack_failures_total'] == 1
