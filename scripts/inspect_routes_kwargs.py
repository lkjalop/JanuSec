import inspect
from src.api.server import app

found = []
for r in app.router.routes:
    dep = getattr(r, 'dependant', None)
    if not dep:
        continue
    qnames = [p.name for p in dep.query_params]
    if 'kwargs' in qnames or 'args' in qnames:
        e = getattr(r, 'endpoint', None)
        sig = getattr(e, '__signature__', None) or (inspect.signature(e) if e else None)
        found.append((r.path, qnames, e, sig))

print('found count', len(found))
for path, q, e, sig in found:
    print(path)
    print('  query params:', q)
    print('  endpoint:', e)
    print('  signature:', sig)
