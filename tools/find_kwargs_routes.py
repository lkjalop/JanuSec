import os
os.environ.setdefault('PYTEST_CURRENT_TEST','1')

from src.api.app import app
from fastapi.dependencies.models import Dependant
import inspect

found = []

def walk_dependant(dep: Dependant, path_stack=None):
    path_stack = path_stack or []
    out = []
    # check query params
    for qp in getattr(dep, 'query_params', []) or []:
        if getattr(qp, 'name', None) == 'kwargs':
            out.append((dep, qp))
    # recurse
    for sub in getattr(dep, 'dependencies', []) or []:
        out.extend(walk_dependant(sub.call, path_stack + [getattr(sub, 'call', None)]))
    return out

for r in app.router.routes:
    try:
        route = r
        dep = getattr(route, 'dependant', None)
        if dep is None:
            continue
        matches = []
        # check top-level
        for qp in getattr(dep, 'query_params', []) or []:
            if getattr(qp, 'name', None) == 'kwargs':
                matches.append((dep, qp))
        # check nested
        for sub in getattr(dep, 'dependencies', []) or []:
            matches.extend(walk_dependant(sub.call))
        if matches:
            for dep_obj, qp in matches:
                owner = getattr(dep_obj, 'call', None) or getattr(dep_obj, 'dependency', None) or dep_obj
                owner_name = getattr(owner, '__name__', str(owner))
                print(f"ROUTE: {getattr(route, 'path', repr(route))} methods={getattr(route,'methods',None)} -> owner={owner_name} param_required={getattr(qp,'required',None)}")
                found.append((route, owner_name, getattr(qp,'required',None)))
    except Exception as e:
        print('ERR', e)

if not found:
    print('No kwargs params found in routes')
else:
    print('\nSummary:')
    for r,o,req in found:
        print(f"{getattr(r,'path',r)} -> {o} required={req}")
