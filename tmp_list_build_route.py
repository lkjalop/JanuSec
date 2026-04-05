from src.api.app import create_app
import json
app = create_app()
found = []
for r in app.routes:
    path = getattr(r, 'path', None)
    if path == '/api/v1/graph/session/build':
        endpoint = getattr(r, 'endpoint', None)
        mod = getattr(endpoint, '__module__', None)
        qual = getattr(endpoint, '__qualname__', None)
        found.append({'path': path, 'route_name': r.name, 'module': mod, 'qualname': qual})
print(json.dumps(found, indent=2))
