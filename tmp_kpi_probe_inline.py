import os
os.environ['PYTEST_CURRENT_TEST']='1'
from src.api.metrics_init import REGISTRY, ensure_metrics
from core.actions.dispatcher import register_metrics
import core.actions.dispatcher as _disp
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
print('has names_to_collectors:', hasattr(REGISTRY,'_names_to_collectors'))
print('key present:', 'janusec_slo_errors_5xx_rate' in getattr(REGISTRY,'_names_to_collectors',{}))
print('dummy_samples keys:', list(getattr(REGISTRY,'_dummy_samples',{}).keys()))
# Manual insertion to verify ds writable
import types as _types
ds = getattr(REGISTRY,'_dummy_samples',None)
if ds is not None:
    lst = ds.setdefault('janusec_slo_errors_5xx_rate', [])
    lst.append(_types.SimpleNamespace(name='janusec_slo_errors_5xx_rate', labels={}, value=0.42))
    print('dummy_samples keys (after manual insert):', list(ds.keys()))
found=False
for fam in REGISTRY.collect():
    if fam.name=='janusec_slo_errors_5xx_rate':
        found=True
        print('fam:', fam.name, 'samples:', [(s.name, s.value) for s in fam.samples])
print('found family:', found)
