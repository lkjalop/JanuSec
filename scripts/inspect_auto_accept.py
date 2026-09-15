import os
import sys
import inspect

PROJ_ROOT = os.path.abspath(os.path.dirname(__file__) + os.sep + '..')
if PROJ_ROOT not in sys.path:
    sys.path.insert(0, PROJ_ROOT)

from src.api.server import app

path = '/api/v1/risk/calibration/auto_accept'
found = None
for r in app.router.routes:
    if getattr(r, 'path', '') == path:
        found = r
        break

if not found:
    print('route not found:', path)
    sys.exit(2)

dep = getattr(found, 'dependant', None)
print('Route:', path)
print('Endpoint:', getattr(found, 'endpoint', None))
ep = getattr(found, 'endpoint', None)
try:
    print('Endpoint __signature__:', getattr(ep, '__signature__', None) or inspect.signature(ep))
except Exception as e:
    print('  signature error:', e)

if dep is None:
    print('No dependant found')
    sys.exit(0)

print('\nDependency query params:')
for p in dep.query_params:
    print(' -', p.name, 'required=', p.required)

print('\nDependency dependencies (flat list):')
deps = getattr(dep, 'dependencies', [])
for d in deps:
    call = getattr(d, 'call', None)
    print(' - dep callable:', call)
    try:
        sig = getattr(call, '__signature__', None) or inspect.signature(call)
        print('   signature:', sig)
    except Exception as e:
        print('   signature error:', e)

print('\nFull dependant tree:')
def dump_dependant(d, indent=0):
    pref = ' ' * indent
    call = getattr(d, 'call', None)
    try:
        sig = getattr(call, '__signature__', None) or (inspect.signature(call) if call else None)
    except Exception:
        sig = 'signature-error'
    print(f"{pref}- call: {call} sig: {sig}")
    for sub in getattr(d, 'dependencies', []) or []:
        dump_dependant(sub, indent+2)

dump_dependant(dep)
