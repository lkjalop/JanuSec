from src.api.app import app
matches = []
for r in app.routes:
    p = getattr(r,'path', None)
    if p and p.startswith('/api/v1/graph/session'):
        endpoint = getattr(r,'endpoint', None)
        epname = getattr(endpoint, '__name__', repr(endpoint))
        epmod = getattr(endpoint, '__module__', None)
        qual = getattr(endpoint, '__qualname__', None)
        matches.append((p, epname, epmod, qual, type(endpoint)))
for m in matches:
    print(m)
