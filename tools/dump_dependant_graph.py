import os
os.environ.setdefault('PYTEST_CURRENT_TEST','1')
from src.api.app import app
from fastapi.dependencies.models import Dependant
import inspect
import sys


def dump_dep(dep, depth=0, seen=None):
    seen = seen or set()
    indent = '  ' * depth
    if dep is None:
        print(f"{indent}- DEP: <None>")
        return
    try:
        call = getattr(dep, 'call', None) or getattr(dep, 'dependency', None) or dep
        name = getattr(call, '__name__', repr(call))
    except Exception:
        name = repr(dep)
    qnames = []
    try:
        qnames = [getattr(q, 'name', None) for q in getattr(dep, 'query_params', []) or []]
    except Exception:
        pass
    bnames = []
    try:
        bnames = [getattr(b, 'name', None) for b in getattr(dep, 'body_params', []) or []]
    except Exception:
        pass
    try:
        req_flag = getattr(dep, 'required', None)
    except Exception:
        req_flag = None
    print(f"{indent}- DEP: {name} query_params={qnames} body_params={bnames} required={req_flag}")
    for sub in getattr(dep, 'dependencies', []) or []:
        try:
            sub_call = getattr(sub, 'call', None) or sub
            key = (getattr(sub_call, '__name__', repr(sub_call)), id(sub))
            if key in seen:
                print(f"{indent}  (already seen {key[0]})")
                continue
            seen.add(key)
            dump_dep(sub.call if hasattr(sub, 'call') else sub, depth+1, seen)
        except Exception as e:
            print(f"{indent}  ERR recursing: {e}")


def inspect_route(path):
    for r in app.router.routes:
        try:
            if getattr(r, 'path', None) == path:
                print('ROUTE', path, 'methods', getattr(r, 'methods', None), file=sys.stderr)
                dep = getattr(r, 'dependant', None)
                dump_dep(dep)
                return
        except Exception as e:
            print('ERR checking route', e, file=sys.stderr)
    print('Route not found', file=sys.stderr)


if __name__ == '__main__':
    inspect_route('/api/v1/graph/reconstruct')
