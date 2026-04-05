import os, asyncio
from core.actions.dispatcher import ActionDispatcher, register_metrics
import core.redaction as redaction
from src.api.metrics_init import REGISTRY, ensure_metrics
from core.actions.models import ActionDecision
class DummySink:
    async def post_action(self, d): pass
class DummySlack:
    async def send_alert(self, sev, text): pass
async def main():
    ensure_metrics(); register_metrics()
    os.environ['DISPATCH_DRY_RUN']='0'
    os.environ['DISPATCH_DISABLE_SLACK']='0'
    os.environ['EVIDENCE_CLASSIFICATION_ENFORCED']='1'
    redaction.classify_evidence = lambda payload: ('RESTRICTED','teams')
    d = ActionDispatcher(DummySink(), DummySlack(), audit_path='artifacts/audit/test_decisions.log')
    dec = ActionDecision(event_id='e2', tenant_id='t1', decision='block', reasons=['test'])
    await d.dispatch(dec)
    # print counters
    out=[]
    for fam in REGISTRY.collect():
        if fam.name in ('policy_blocked','janusec_policy_blocked'):
            out.append((fam.name, [(s.name, s.labels, s.value) for s in fam.samples]))
    print(out)
asyncio.run(main())
