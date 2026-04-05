import os
os.environ['PLATFORM_LITE_INIT']='1'
from src.api.app import app
routes = sorted({getattr(r,'path',str(r)) for r in app.router.routes})
print(len(routes))
for p in routes:
    if '/subscriptions' in p or 'msgraph' in p or 'gmail' in p:
        print(p)
print('HAS exact /api/v1/subscriptions/msgraph/callback?', '/api/v1/subscriptions/msgraph/callback' in routes)
