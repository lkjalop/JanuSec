import os
os.environ.setdefault('TEST_HELPERS_ENABLED','1')
os.environ.setdefault('PLATFORM_LITE_INIT','1')
from src.api.app import app
routes = sorted({getattr(r,'path',None) for r in app.router.routes})
for r in routes:
    if r:
        print(r)
