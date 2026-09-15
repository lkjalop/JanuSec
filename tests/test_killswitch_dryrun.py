import asyncio
from core.actions.dispatcher import ActionDispatcher
from core.actions.models import ActionDecision


class DummySink:
    def __init__(self):
        self.calls = 0
    async def post_action(self, decision):
        self.calls += 1


class DummySlack:
    def __init__(self):
        self.calls = 0
    async def send_alert(self, sev, text):
        self.calls += 1


async def _run(dispatcher, decision):
    await dispatcher.dispatch(decision)
    await asyncio.sleep(0.05)


def test_global_dry_run(monkeypatch):
    monkeypatch.setenv('DRY_RUN','1')
    monkeypatch.setenv('DISPATCH_DISABLE_SLACK','0')
    monkeypatch.setenv('DISPATCH_DISABLE_ECLIPSE','0')
    sink = DummySink()
    slack = DummySlack()
    d = ActionDispatcher(sink, slack, audit_path='artifacts/audit/test_decisions.log')
    dec = ActionDecision(event_id='k1', tenant_id='t1', decision='block', reasons=['x'], severity=0.5, quality=None, factors=['scenario:high'], risk_context={}, ts=0)
    asyncio.run(_run(d, dec))
    # Dry-run prevents both sinks from being called
    assert sink.calls == 0
    assert slack.calls == 0


def test_per_tenant_dry_run(monkeypatch):
    monkeypatch.setenv('DRY_RUN','0')
    monkeypatch.setenv('DRY_RUN_TENANTS','t2')
    sink = DummySink(); slack = DummySlack()
    d = ActionDispatcher(sink, slack, audit_path='artifacts/audit/test_decisions.log')
    dec = ActionDecision(event_id='k2', tenant_id='t2', decision='block', reasons=['x'], severity=0.5, quality=None, factors=['scenario:high'], risk_context={}, ts=0)
    asyncio.run(_run(d, dec))
    assert sink.calls == 0
    assert slack.calls == 0


def test_killswitch_disable_slack(monkeypatch):
    monkeypatch.setenv('DRY_RUN','0')
    monkeypatch.setenv('DISPATCH_DISABLE_SLACK','1')
    monkeypatch.setenv('DISPATCH_DISABLE_ECLIPSE','0')
    sink = DummySink(); slack = DummySlack()
    d = ActionDispatcher(sink, slack, audit_path='artifacts/audit/test_decisions.log')
    dec = ActionDecision(event_id='k3', tenant_id='t3', decision='block', reasons=['x'], severity=0.5, quality=None, factors=['scenario:high'], risk_context={}, ts=0)
    asyncio.run(_run(d, dec))
    # Slack disabled; Eclipse may still be queued or executed synchronously under pytest
    assert slack.calls == 0


def test_killswitch_disable_eclipse(monkeypatch):
    monkeypatch.setenv('DRY_RUN','0')
    monkeypatch.setenv('DISPATCH_DISABLE_SLACK','0')
    monkeypatch.setenv('DISPATCH_DISABLE_ECLIPSE','1')
    sink = DummySink(); slack = DummySlack()
    d = ActionDispatcher(sink, slack, audit_path='artifacts/audit/test_decisions.log')
    dec = ActionDecision(event_id='k4', tenant_id='t4', decision='block', reasons=['x'], severity=0.5, quality=None, factors=['scenario:high'], risk_context={}, ts=0)
    asyncio.run(_run(d, dec))
    # Eclipse disabled; Slack may be called unless classification blocks
    # Just assert that Eclipse wasn't called
    assert sink.calls == 0
