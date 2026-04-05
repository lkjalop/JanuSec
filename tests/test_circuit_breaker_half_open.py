import os
import pytest


class _DummySlack:
    def __init__(self, fail_times=0):
        self.calls = 0
        self.fail_times = fail_times

    async def send_alert(self, sev, text):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise RuntimeError('slack_fail')


@pytest.mark.asyncio
async def test_cb_half_open_trials(monkeypatch, tmp_path):
    # Enable CB for slack; set thresholds
    monkeypatch.setenv('CB_ENABLED', '1')
    monkeypatch.setenv('CB_SLACK_ENABLED', '1')
    monkeypatch.setenv('CB_FAIL_THRESHOLD', '2')
    monkeypatch.setenv('CB_RESET_SECONDS', '0.1')
    monkeypatch.setenv('CB_HALF_OPEN_TRIALS', '1')
    # Ensure pytest deterministic path
    monkeypatch.setenv('PYTEST_CURRENT_TEST', '1')

    from src.core.actions.dispatcher import ActionDispatcher, register_metrics
    from src.core.actions.models import ActionDecision

    # dummy eclipse sink does nothing
    eclipse = None
    slack = _DummySlack(fail_times=2)
    audit_path = tmp_path / 'audit.log'
    d = ActionDispatcher(eclipse, slack, audit_path=str(audit_path))
    register_metrics()

    # First two attempts fail -> opens breaker
    dec = ActionDecision(event_id='e1', tenant_id='t1', decision='block', reasons=['x'], severity=0.9, quality=1.0, factors=['f'])
    await d.dispatch(dec)
    await d.dispatch(dec)

    # Wait for reset window to enter half-open
    import asyncio
    await asyncio.sleep(0.11)

    # Half-open allows one trial; now dummy slack no longer fails
    slack.fail_times = 0
    calls_before = slack.calls
    await d.dispatch(dec)
    assert slack.calls == calls_before + 1


@pytest.mark.asyncio
async def test_cb_half_open_failure_reopens(monkeypatch, tmp_path):
    # Enable CB with low threshold so one failure opens it
    monkeypatch.setenv('CB_ENABLED', '1')
    monkeypatch.setenv('CB_SLACK_ENABLED', '1')
    monkeypatch.setenv('CB_FAIL_THRESHOLD', '1')
    monkeypatch.setenv('CB_RESET_SECONDS', '0.1')
    monkeypatch.setenv('CB_HALF_OPEN_TRIALS', '1')
    monkeypatch.setenv('PYTEST_CURRENT_TEST', '1')

    from src.core.actions.dispatcher import ActionDispatcher, register_metrics
    from src.core.actions.models import ActionDecision

    slack = _DummySlack(fail_times=100)  # always fail
    audit_path = tmp_path / 'audit2.log'
    d = ActionDispatcher(None, slack, audit_path=str(audit_path))
    register_metrics()

    dec = ActionDecision(event_id='e2', tenant_id='t2', decision='block', reasons=['x'], severity=0.9, quality=1.0, factors=['f'])

    # First call fails and opens breaker
    await d.dispatch(dec)
    calls1 = slack.calls
    assert calls1 == 1

    # Wait for reset to move to half-open
    import asyncio
    await asyncio.sleep(0.11)

    # Half-open trial allowed but fails; should re-open
    await d.dispatch(dec)
    calls2 = slack.calls
    assert calls2 == calls1 + 1

    # Immediately try again; should NOT attempt due to reopened breaker
    await d.dispatch(dec)
    assert slack.calls == calls2
