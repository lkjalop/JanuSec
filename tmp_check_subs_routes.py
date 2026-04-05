import os
os.environ['PLATFORM_LITE_INIT']='1'
from src.api.app import app
routes = sorted({getattr(r,'path',str(r)) for r in app.router.routes})
subs = [p for p in routes if p.startswith('/api/v1/subscriptions')]
print('Found subscriptions routes:', subs)
