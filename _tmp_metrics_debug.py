import os, asyncio
os.environ['PYTHONPATH']='src'
from core.actions.dispatcher import ActionDispatcher, register_metrics
from src.api.metrics_init import REGISTRY, ensure_metrics

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

async def main():
    register_metrics()
    ensure_metrics()
    os.environ['DISPATCH_DRY_RUN']='0'
    os.environ['DISPATCH_DISABLE_SLACK']='0'
    os.environ['DISPATCH_DISABLE_ECLIPSE']='0'
    os.environ['EVIDENCE_CLASSIFICATION_ENFORCED']='0'
    from core.actions.models import ActionDecision
    sink = DummySink(True)
    slack = DummySlack(True)
    d = ActionDispatcher(sink, slack, audit_path='artifacts/audit/test_decisions.log')
    dec = ActionDecision(event_id='e1', tenant_id='t1', decision='block', reasons=['test'], severity=0.9, quality=None, factors=[], risk_context={}, ts=0)
    await d.dispatch(dec)
    await asyncio.sleep(0.1)
    # Read counters
    def read_counter(name, labels=None):
        total = 0.0
        for fam in REGISTRY.collect():
            if fam.name == name:
                for s in fam.samples:
                    if labels is None or all(s.labels.get(k)==v for k,v in labels.items()):
                        total += s.value
        return total
    print('playbook_failures_total slack_send_error =', read_counter('playbook_failures_total', {'type':'slack_send_error'}))
    print('playbook_failures_total eclipse_post_error =', read_counter('playbook_failures_total', {'type':'eclipse_post_error'}))
    print('janusec_playbook_failures_total slack_send_error =', read_counter('janusec_playbook_failures_total', {'type':'slack_send_error'}))

if __name__ == '__main__':
    asyncio.run(main())
