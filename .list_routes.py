import os, json
os.environ['PLATFORM_LITE_INIT'] = '1'
from src.api.app import app
routes = sorted([(getattr(r,'path',None), list(getattr(r, 'methods', []))) for r in app.routes])
print('ROUTES:')
for p,m in routes:
    print(p, m)
print('total', len(routes))
