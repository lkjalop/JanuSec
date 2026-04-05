from src.api.app import app
routes = [getattr(r,'path',None) for r in app.router.routes if getattr(r,'path',None) is not None]
found = [r for r in routes if '/api/v1/admin/arc' in r]
print('found_len=', len(found))
for r in found:
    print(r)
print('Total routes:', len(routes))
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.api.app import app

routes = []
for route in app.routes:
    routes.append({
        'path': route.path,
        'name': route.name,
        'methods': list(getattr(route, 'methods', []))
    })

import json
print(json.dumps(routes, indent=2))