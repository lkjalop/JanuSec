from src.api.app import create_app
app = create_app()
for r in app.router.routes:
    p = getattr(r, 'path', None)
    if p and p.startswith('/api/v1/graph'):
        print(p, getattr(r, 'name', None), getattr(r.endpoint, '__module__', None), getattr(r.endpoint, '__name__', None))
print('--- total routes:', len([r for r in app.router.routes if getattr(r,'path',None) and r.path.startswith('/api/v1/graph')]))
