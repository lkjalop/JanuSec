import sys
sys.path.insert(0,'.')
from src.api.server import app
for r in app.routes:
    path = getattr(r,'path', None) or getattr(r,'path_format', None) or ''
    if '/api/v1/events' in str(path):
        print('Route:', path, 'methods:', getattr(r,'methods', None), 'name:', getattr(r,'name', None))
        ep = getattr(r,'endpoint', None)
        print(' endpoint module:', getattr(ep,'__module__', None))
        print(' endpoint qualname:', getattr(ep,'__qualname__', None))
print('--- done')
