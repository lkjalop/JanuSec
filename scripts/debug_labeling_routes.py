from src.api.app import app
paths = sorted([r.path for r in app.router.routes if hasattr(r,'path')])
print('labeling routes:')
for p in paths:
    if p.startswith('/api/v1/labeling'):
        print(p)
print('\nadmin calibration:')
for p in paths:
    if p.startswith('/api/v1/admin/calibration'):
        print(p)
