import sys
sys.path.insert(0, '.')
from src.api.server import app

for r in app.routes:
    try:
        path = getattr(r, 'path', None) or getattr(r, 'path_format', None) or getattr(r, 'url', None)
        name = getattr(r, 'name', None)
        endpoint = getattr(r, 'endpoint', None)
        methods = getattr(r, 'methods', None)
        if path and '/api/v1/events' in str(path):
            print('Route:', path, 'methods:', methods, 'name:', name)
            try:
                print(' endpoint:', endpoint)
                print(' endpoint module:', getattr(endpoint, '__module__', None))
                print(' endpoint qualname:', getattr(endpoint, '__qualname__', None))
            except Exception as e:
                print(' endpoint introspect error', e)
        except_routes = [r for r in app.routes if '/api/v1/events' in (getattr(r,'path', '') or getattr(r,'path_format','') or '')]
        print('Found routes count:', len(except_routes))
