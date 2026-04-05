from src.api.server import app
for r in app.router.routes:
    if getattr(r, 'path', '') == '/api/v1/endpoints/log_batch':
        print('route found', r.name, type(r))
        try:
            print('endpoint', r.endpoint)
        except Exception as e:
            print('no endpoint attr', e)
