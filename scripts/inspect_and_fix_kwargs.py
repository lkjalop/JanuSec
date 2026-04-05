"""Inspect FastAPI routes for query params named 'args' or 'kwargs' and
attempt to patch wrapped callables so they preserve the original signature.

Run this from the repository root (it will add the project root to sys.path).
"""
import os
import sys
import inspect

PROJ_ROOT = os.path.abspath(os.path.dirname(__file__) + os.sep + '..')
if PROJ_ROOT not in sys.path:
    sys.path.insert(0, PROJ_ROOT)

from src.api.server import app

issues = []
patched = []

for r in app.router.routes:
    dep = getattr(r, 'dependant', None)
    if not dep:
        continue
    qnames = [p.name for p in dep.query_params]
    if 'kwargs' in qnames or 'args' in qnames:
        endpoint = getattr(r, 'endpoint', None)
        ep_sig = getattr(endpoint, '__signature__', None) or (inspect.signature(endpoint) if endpoint else None)
        issues.append((r.path, qnames, endpoint, ep_sig))

print('Found routes with args/kwargs query params:', len(issues))

for path, qnames, endpoint, ep_sig in issues:
    print('\nRoute:', path)
    print('  query params:', qnames)
    print('  endpoint:', endpoint)
    print('  endpoint signature:', ep_sig)

    # Inspect dependant.call (the underlying dependency function)
    try:
        call = getattr(r.dependant, 'call', None)
        if call is not None:
            csig = getattr(call, '__signature__', None) or inspect.signature(call)
            print('  dependant.call:', call)
            print('  dependant.call signature:', csig)
            # If dependant.call exposes VAR_KEYWORD, try to patch from __wrapped__
            if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in csig.parameters.values()):
                orig = getattr(call, '__wrapped__', None)
                if orig:
                    try:
                        call.__signature__ = inspect.signature(orig)
                        patched.append((call, orig))
                        print('    -> patched dependant.call.__signature__ from __wrapped__')
                    except Exception as e:
                        print('    -> failed to patch dependant.call:', e)
    except Exception as e:
        print('  error inspecting dependant.call:', e)

    # If endpoint is a wrapper exposing VAR_KEYWORD, attempt to patch
    try:
        if endpoint is not None:
            esig = getattr(endpoint, '__signature__', None) or inspect.signature(endpoint)
            if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in esig.parameters.values()):
                orig_e = getattr(endpoint, '__wrapped__', None)
                if orig_e:
                    try:
                        endpoint.__signature__ = inspect.signature(orig_e)
                        patched.append((endpoint, orig_e))
                        print('    -> patched endpoint.__signature__ from __wrapped__')
                    except Exception as e:
                        print('    -> failed to patch endpoint:', e)
    except Exception as e:
        print('  error inspecting endpoint:', e)

print('\nPatched count:', len(patched))
for t, o in patched:
    print('Patched', t, 'from', o)
