import asyncio
from core.actions.dispatcher import ActionDispatcher
from core.actions.models import ActionDecision
from core.flags import get_flag


class FailingSink:
    def __init__(self):
        self.calls = 0
    async def post_action(self, decision):
        self.calls += 1
        raise RuntimeError('boom')


class NoopSlack:
    def __init__(self):
        self.calls = 0
    async def send_alert(self, sev, text):
        self.calls += 1


async def _run(dispatcher, decision):
    await dispatcher.dispatch(decision)
    await asyncio.sleep(0.02)


def test_circuit_breaker_opens_for_eclipse(monkeypatch):
    monkeypatch.setenv('CB_ENABLED','1')
    monkeypatch.setenv('CB_ECLIPSE_ENABLED','1')
    monkeypatch.setenv('CB_FAIL_THRESHOLD','2')
    monkeypatch.setenv('CB_RESET_SECONDS','60')
    sink = FailingSink()
    slack = NoopSlack()
    d = ActionDispatcher(sink, slack, audit_path='artifacts/audit/test_decisions.log')
    dec = ActionDecision(event_id='cb-1', tenant_id='t1', decision='block', reasons=['x'], severity=0.5, quality=None, factors=['scenario:high'], risk_context={}, ts=0)
    # First two attempts should call sink and fail; third should be gated by CB
    asyncio.run(_run(d, dec))
    asyncio.run(_run(d, dec))
    before = sink.calls
    asyncio.run(_run(d, dec))
    after = sink.calls
    assert before == 2
    # Third dispatch was gated (no new call to sink)
    assert after == before
