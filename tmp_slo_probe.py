import os, asyncio
os.environ['EVIDENCE_CLASSIFICATION_ENFORCED']='0'
os.environ['PYTEST_CURRENT_TEST']='1'
from src.api.metrics_init import REGISTRY, ensure_metrics
from src.core.actions.dispatcher import ActionDispatcher, register_metrics
from src.core.actions.models import ActionDecision
class DummySink:
    def __init__(self, should_fail=False):
        self.should_fail=should_fail
    async def post_action(self, d):
        if self.should_fail:
            raise RuntimeError('boom')
class DummySlack:
    def __init__(self, should_fail=False):
        self.should_fail=should_fail
    async def send_alert(self, sev, text):
        if self.should_fail:
            raise RuntimeError('boom')
ensure_metrics(); register_metrics()
sink=DummySink(False); slack=DummySlack(False)
d=ActionDispatcher(sink, slack, audit_path='artifacts/audit/test_decisions.log')
dec=ActionDecision(event_id='slo-s1', tenant_id='t1', decision='block', reasons=['test'], severity=0.4, quality=None, factors=['scenario:high'], risk_context={}, ts=0)
async def run():
    await d.dispatch(dec)
asyncio.run(run())
print('REGISTRY type:', type(REGISTRY))
print('dummy samples keys:', list(getattr(REGISTRY,'_dummy_samples',{}).keys()))
for fam in REGISTRY.collect():
    print('fam:', fam.name, 'samples:', [(getattr(s,'name',None), getattr(s,'value',None)) for s in fam.samples])
