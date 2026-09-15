"""Scan FastAPI routes and their dependencies for callables that expose `kwargs` or `**kwargs` in their signatures."""
import os
os.environ['PYTEST_CURRENT_TEST'] = '1'
os.environ['TEST_HELPERS_ENABLED'] = '1'

from src.api.server import app
import inspect

issues = []
for r in app.router.routes:
    dep = getattr(r, 'dependant', None)
    if not dep:
        continue
    for sub in dep.dependencies or []:
        fn = getattr(sub, 'call', None)
        if not fn:
            continue
        try:
            sig = inspect.signature(fn)
        except Exception:
            continue
        params = sig.parameters
        for pname, p in params.items():
            if pname == 'kwargs' and (p.default is inspect._empty):
                issues.append((r.path, fn, 'param_kwargs_no_default', sig))
            if p.kind == inspect.Parameter.VAR_KEYWORD:
                issues.append((r.path, fn, 'var_keyword', sig))

# dedupe by function
seen = set()
for path, fn, typ, sig in issues:
    key = (fn.__module__, getattr(fn, '__name__', str(fn)))
    if key in seen:
        continue
    seen.add(key)
    print('Issue type:', typ)
    print(' Route:', path)
    print(' Function:', fn)
    print(' Signature:', sig)
    print(' Module:', fn.__module__)
    print('----')
print('Scan complete. Total issues:', len(seen))
