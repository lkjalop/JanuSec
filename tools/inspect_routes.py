import os, json, inspect
os.environ['PYTEST_CURRENT_TEST'] = '1'
# Import app and inspect route metadata
try:
    from src.api.app import app
except Exception as e:
    print('import app failed', e)
    raise

path = '/api/v1/graph/reconstruct'
found = False
for r in app.router.routes:
    if getattr(r, 'path', None) == path:
        found = True
        print('ROUTE FOUND:', r)
        ep = getattr(r, 'endpoint', None)
        print('ENDPOINT:', repr(ep))
        try:
            print('SIGNATURE:', inspect.signature(ep))
        except Exception as e:
            print('SIGNATURE ERROR:', e)
        dep = getattr(r, 'dependant', None)
        if dep:
            qp = [p.name for p in getattr(dep, 'query_params', [])]
            bp = [p.name for p in getattr(dep, 'body_params', [])]
            pp = [p.name for p in getattr(dep, 'path_params', [])]
            print('DEPENDANT QUERY PARAMS:', qp)
            print('DEPENDANT BODY PARAMS:', bp)
            print('DEPENDANT PATH PARAMS:', pp)
            # Inspect nested dependencies
            try:
                for d in getattr(dep, 'dependencies', []) or []:
                    call = getattr(d, 'call', None)
                    name = getattr(call, '__name__', repr(call))
                    params = [p.name for p in getattr(d, 'query_params', [])]
                    print('  NESTED DEP:', name, 'query_params=', params, 'required=', getattr(d, 'required', None))
            except Exception as e:
                print('  nested inspect error', e)
        try:
            op = app.openapi().get('paths', {}).get(path)
            print('OPENAPI OP:', json.dumps(op, indent=2))
        except Exception as e:
            print('OPENAPI ERROR:', e)

if not found:
    print('Route not found in app.router.routes')
