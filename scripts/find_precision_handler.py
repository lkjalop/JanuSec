import os
os.environ.setdefault('PLATFORM_LITE_INIT','1')
from src.api.app import app
for r in app.router.routes:
    p = getattr(r,'path',None)
    if p == '/api/v1/metrics/precision/daily':
        print('Route:', p)
        ep = getattr(r,'endpoint',None)
        if ep:
            print('  handler:', ep.__module__, getattr(ep,'__name__',repr(ep)))
