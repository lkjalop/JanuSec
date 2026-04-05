from src.api.app import app
for r in app.router.routes:
    try:
        if getattr(r,'path',None) == '/api/v1/graph/session/build':
            print('Route:', r.path, 'name:', getattr(r,'name',None), 'endpoint:', r.endpoint)
    except Exception:
        pass
