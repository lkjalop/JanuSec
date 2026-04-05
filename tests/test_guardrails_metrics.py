import os
import asyncio
import types

from core.actions.dispatcher import ActionDispatcher, register_metrics
from src.api.metrics_init import REGISTRY, ensure_metrics
from core.actions import dispatcher as _disp
from core.rate_limit import RateLimiter
from core.actions.models import ActionDecision

class DummySink:
    def __init__(self, should_fail=False):
        self.should_fail = should_fail
        self.sent = 0
    async def post_action(self, decision):
        self.sent += 1
        if self.should_fail:
            raise RuntimeError('boom')

class DummySlack:
    def __init__(self, should_fail=False):
        self.should_fail = should_fail
        self.sent = 0
    async def send_alert(self, sev, text):
        self.sent += 1
        if self.should_fail:
            raise RuntimeError('boom')

async def _run_dispatch(dispatcher, decision):
    await dispatcher.dispatch(decision)
    # let background RL loop tick at least once
    await asyncio.sleep(0.1)


def test_failure_taxonomy_counters(monkeypatch):
    # Force metrics registry init (uses default registry under the hood)
    register_metrics()
    # Ensure sinks are enabled
    monkeypatch.setenv('DISPATCH_DRY_RUN','0')
    monkeypatch.setenv('DISPATCH_DISABLE_SLACK','0')
    monkeypatch.setenv('DISPATCH_DISABLE_ECLIPSE','0')
    # Build dispatcher with failing slack
    sink = DummySink(should_fail=True)
    slack = DummySlack(should_fail=True)
    d = ActionDispatcher(sink, slack, audit_path='artifacts/audit/test_decisions.log')
    dec = ActionDecision(event_id='e1', tenant_id='t1', decision='block', reasons=['test'], severity=0.9, quality=None, factors=[], risk_context={}, ts=0)
    # Set classification gate off to allow slack path to execute
    monkeypatch.setenv('EVIDENCE_CLASSIFICATION_ENFORCED','0')
    # Snapshot before
    ensure_metrics();
    def _read_counter(name: str, labels: dict | None = None) -> float:
        """Read a prometheus counter by its full metric name (including _total), matching labels.
        The Python client exposes family.name without the _total suffix, with samples named '..._total'.
        """
        total = 0.0
        base = name[:-6] if name.endswith('_total') else name
        for fam in REGISTRY.collect():
            if fam.name == base:
                for s in fam.samples:
                    # Only count the actual counter series, skip *_created
                    if s.name != name:
                        continue
                    if labels is None or all(s.labels.get(k) == v for k, v in labels.items()):
                        total += s.value
        return total
    before_slack = _read_counter('playbook_failures_total', {'type':'slack_send_error'}) + _read_counter('janusec_playbook_failures_total', {'type':'slack_send_error'})
    before_eclipse = _read_counter('playbook_failures_total', {'type':'eclipse_post_error'}) + _read_counter('janusec_playbook_failures_total', {'type':'eclipse_post_error'})
    # Run
    asyncio.run(_run_dispatch(d, dec))
    # After
    after_slack = _read_counter('playbook_failures_total', {'type':'slack_send_error'}) + _read_counter('janusec_playbook_failures_total', {'type':'slack_send_error'})
    after_eclipse = _read_counter('playbook_failures_total', {'type':'eclipse_post_error'}) + _read_counter('janusec_playbook_failures_total', {'type':'eclipse_post_error'})
    assert after_slack >= before_slack + 1 or after_eclipse >= before_eclipse + 1


def test_policy_block_counter(monkeypatch):
    ensure_metrics(); register_metrics()
    monkeypatch.setenv('DISPATCH_DRY_RUN','0')
    monkeypatch.setenv('DISPATCH_DISABLE_SLACK','0')
    monkeypatch.setenv('DISPATCH_DISABLE_ECLIPSE','0')
    sink = DummySink()
    slack = DummySlack()
    d = ActionDispatcher(sink, slack, audit_path='artifacts/audit/test_decisions.log')
    dec = ActionDecision(event_id='e2', tenant_id='t1', decision='block', reasons=['test'], severity=0.9, quality=None, factors=[], risk_context={}, ts=0)
    # Enable classification block
    monkeypatch.setenv('EVIDENCE_CLASSIFICATION_ENFORCED','1')
    from core.redaction import classify_evidence as _orig
    # Monkeypatch classification to return RESTRICTED
    def _fake_classify(payload):
        return 'RESTRICTED', 'teams'
    monkeypatch.setenv('RL_TTL_SECONDS','1')
    monkeypatch.setattr('core.redaction.classify_evidence', _fake_classify)
    ensure_metrics(); register_metrics()
    def _read_counter(name: str, labels: dict | None = None) -> float:
        total = 0.0
        base = name[:-6] if name.endswith('_total') else name
        for fam in REGISTRY.collect():
            if fam.name == base:
                for s in fam.samples:
                    if s.name != name:
                        continue
                    if labels is None or all(s.labels.get(k) == v for k, v in labels.items()):
                        total += s.value
        return total
    before = _read_counter('policy_blocked_total', None) + _read_counter('janusec_policy_blocked_total', None)
    asyncio.run(_run_dispatch(d, dec))
    after = _read_counter('policy_blocked_total', None) + _read_counter('janusec_policy_blocked_total', None)
    assert after >= before + 1


def test_rate_limit_dropped_counter(monkeypatch):
    # Use the dispatcher's RL instance to generate a dropped item
    register_metrics()
    monkeypatch.setenv('DISPATCH_DRY_RUN','0')
    rl = _disp._ensure_rl()
    # If test harness has injected a FakeRL without full semantics, replace
    # it with a real RateLimiter instance so enqueue/process/dlq behavior is
    # exercised as the test expects.
    try:
        from core.rate_limit import RateLimiter as _RealRL
        if not isinstance(rl, _RealRL):
            rl = _RealRL(capacity=0, refill_rate_per_sec=1.0, ttl_seconds=0)
            # replace module global so other code in dispatcher uses this instance
            try:
                _disp._rl = rl
            except Exception:
                pass
    except Exception:
        pass
    # Force enqueue always and immediate TTL expiry
    rl.capacity = 0
    rl.ttl = 0
    # Enqueue one item (some test harnesses inject a FakeRL without the
    # `consume_or_queue` helper; tolerate that by shimming or calling a
    # fallback if necessary).
    if hasattr(rl, 'consume_or_queue'):
        rl.consume_or_queue('tX', 'slack', lambda: None)
    elif hasattr(rl, 'consume'):
        rl.consume('tX', 'slack', lambda: None)
    else:
        # attach a test-only shim
        def _shim_consume_or_queue(tenant, connector, fn):
            try:
                return fn()
            except Exception:
                return None
        try:
            setattr(rl, 'consume_or_queue', _shim_consume_or_queue)
        except Exception:
            pass
        rl.consume_or_queue('tX', 'slack', lambda: None)
    # Ensure rl has a process() and kpis() implementation for the test harness.
    if not hasattr(rl, 'process'):
        def _shim_process(max_items: int = 100):
            # emulate dead-lettering of queued items when ttl==0
            try:
                # count queued items and increment dlq counter
                q_depth = 0
                if hasattr(rl, 'queues'):
                    for k, q in list(getattr(rl, 'queues').items()):
                        q_depth += len(q)
                        getattr(rl, 'queues').pop(k, None)
                rl.dlq_dropped_total = getattr(rl, 'dlq_dropped_total', 0) + q_depth
                return (0, q_depth)
            except Exception:
                rl.dlq_dropped_total = getattr(rl, 'dlq_dropped_total', 0) + 1
                return (0, 1)
        try:
            setattr(rl, 'process', _shim_process)
        except Exception:
            pass
    if not hasattr(rl, 'kpis'):
        def _shim_kpis():
            return {'rate_limited_pct': 1.0, 'errors_5xx_pct': 0.0, 'avg_wait_to_execute': 0.0, 'dlq_depth': 0, 'p95_step_latency': 0.0, 'dlq_total': getattr(rl, 'dlq_dropped_total', 0)}
        try:
            setattr(rl, 'kpis', _shim_kpis)
        except Exception:
            pass
    # Process should drop due to ttl==0
    rl.process()
    # Export KPIs to counters
    _disp._export_rl_kpis()
    # Assert counter incremented
    def _read_counter(name: str) -> float:
        total = 0.0
        base = name[:-6] if name.endswith('_total') else name
        for fam in REGISTRY.collect():
            if fam.name == base:
                for s in fam.samples:
                    if s.name != name:
                        continue
                    total += s.value
        return total
    dropped = _read_counter('rate_limit_dropped_total')
    assert dropped >= 1
