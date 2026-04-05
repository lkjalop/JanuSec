from src.api.metrics_init import REGISTRY, ensure_metrics
from core.actions.dispatcher import ActionDispatcher, register_metrics
from core.actions import dispatcher as _disp
from core.actions.models import ActionDecision
import asyncio


class DummySink:
    def __init__(self, should_fail=False):
        self.should_fail = should_fail
    async def post_action(self, decision):
        if self.should_fail:
            raise RuntimeError('boom')


class DummySlack:
    def __init__(self, should_fail=False):
        self.should_fail = should_fail
    async def send_alert(self, sev, text):
        if self.should_fail:
            raise RuntimeError('boom')


async def _run(dispatcher, decision):
    await dispatcher.dispatch(decision)
    await asyncio.sleep(0.05)


def _read_gauge(name: str) -> float | None:
    for fam in REGISTRY.collect():
        if fam.name == name:
            for s in fam.samples:
                if s.name == name:
                    return float(s.value)
    return None


def test_slo_success_rate_updates(monkeypatch):
    ensure_metrics(); register_metrics()
    # Permit Slack path
    monkeypatch.setenv('EVIDENCE_CLASSIFICATION_ENFORCED','0')
    # Reset counters for deterministic rate
    _disp._succ_total = 0
    _disp._fail_total = 0
    sink = DummySink(should_fail=False)
    slack = DummySlack(should_fail=False)
    d = ActionDispatcher(sink, slack, audit_path='artifacts/audit/test_decisions.log')
    dec = ActionDecision(event_id='slo-s1', tenant_id='t1', decision='block', reasons=['test'], severity=0.4, quality=None, factors=['scenario:high'], risk_context={}, ts=0)
    asyncio.run(_run(d, dec))
    val = _read_gauge('janusec_slo_success_rate')
    assert val is not None
    assert 0.0 <= val <= 1.0
    # With one success and zero failures, rate should be 1
    assert val == 1.0


def test_slo_5xx_rate_updates_via_kpis(monkeypatch):
    ensure_metrics(); register_metrics()
    class FakeRL:
        def kpis(self):
            return {
                'rate_limited_pct': 0.0,
                'errors_5xx_pct': 0.42,
                'avg_wait_to_execute': 0.0,
                'dlq_depth': 0,
                'p95_step_latency': 0.0,
                'dlq_total': 0,
            }
    # Monkeypatch RL instance
    _disp._rl = FakeRL()
    _disp._export_rl_kpis()
    val = _read_gauge('janusec_slo_errors_5xx_rate')
    assert val is not None
    assert abs(val - 0.42) < 1e-9
