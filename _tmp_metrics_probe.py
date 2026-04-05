import os
os.environ.setdefault('PYTEST_CURRENT_TEST','1')
os.environ.setdefault('METRICS_DEBUG','1')
from src.api.metrics_init import REGISTRY, ensure_metrics
from core.actions.dispatcher import register_metrics
from core.actions import dispatcher as _disp

def run_probe():
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
    _disp._rl = FakeRL()
    _disp._export_rl_kpis()
    print('REG:', type(REGISTRY))
    try:
        fams = list(REGISTRY.collect())
        print('families:', [getattr(f,'name',None) for f in fams])
        for f in fams:
            if getattr(f,'name', None)=='janusec_slo_errors_5xx_rate':
                print('samples:', [(s.name, s.value, getattr(s,'labels',{})) for s in getattr(f,'samples',[])])
    except Exception as e:
        print('collect error', e)
    print('ds:', getattr(REGISTRY,'_dummy_samples', None))
    print('dn:', getattr(REGISTRY,'_dummy_names', None))

if __name__ == '__main__':
    run_probe()
