from src.api.app import app
paths = sorted([r.path for r in app.router.routes if hasattr(r,'path')])
for p in paths:
    if p.startswith('/api/v1/admin/calibration'):
        print('FOUND', p)
print('total routes count', len(paths))
