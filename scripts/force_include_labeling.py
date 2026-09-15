from src.api.app import app
from importlib import import_module
m = import_module('src.api.labeling_endpoints')
app.include_router(m.router)
print('Included labeling router forcefully')
for p in sorted([r.path for r in app.router.routes if hasattr(r,'path')]):
    if p.startswith('/api/v1/labeling'):
        print(p)
