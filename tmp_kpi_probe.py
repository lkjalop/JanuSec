import os
from src.api.metrics_init import REGISTRY, ensure_metrics
from src.core.actions import dispatcher as _disp
from src.core.actions.dispatcher import register_metrics
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
ensure_metrics(); register_metrics()
_disp._rl = FakeRL()
_disp._export_rl_kpis()
print('REGISTRY type:', type(REGISTRY))
print('dummy samples keys:', list(getattr(REGISTRY,'_dummy_samples',{}).keys()))
for fam in REGISTRY.collect():
    print('fam:', fam.name, 'samples:', [(getattr(s,'name',None), getattr(s,'value',None)) for s in fam.samples])
