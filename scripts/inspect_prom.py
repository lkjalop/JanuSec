import os
os.environ.setdefault('PLATFORM_LITE_INIT', '1')
os.environ.setdefault('METRICS_DEBUG', '1')
import importlib
# Import the tests conftest to ensure wrapped registry is installed
try:
    import tests.conftest as tc
except Exception as e:
    print('import tests.conftest failed', e)
import prometheus_client as prom
reg = getattr(prom, 'REGISTRY', None)
print('prom.REGISTRY id=', id(reg), 'type=', type(reg))
print('reg._dummy_samples=', getattr(reg, '_dummy_samples', None))
try:
    items = list(reg.collect())
    print('collect items count=', len(items))
    for f in items:
        print('fam', getattr(f, 'name', None), 'samples:', [(getattr(s,'name',None), getattr(s,'value',None), getattr(s,'labels',None)) for s in getattr(f,'samples',[])])
except Exception as e:
    print('collect raised', e)
print('done')
