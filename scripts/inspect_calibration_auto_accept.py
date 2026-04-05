import inspect
from src.api.server import app

path = '/api/v1/risk/calibration/auto_accept'
for r in app.router.routes:
    if getattr(r,'path',None)==path:
        dep = getattr(r,'dependant', None)
        print('route', r.path, 'endpoint', getattr(r,'endpoint',None))
        if not dep:
            print(' no dependant')
            continue
        qnames = [p.name for p in dep.query_params]
        print(' query params on route dependant:', qnames)
        # show dependencies
        def show_dep(d, level=0):
            if not d:
                return
            prefix = '  '*level
            print(prefix+'dep call:', getattr(d,'call',None))
            try:
                q = [p.name for p in d.query_params]
                print(prefix+'  query_params:', q)
            except Exception as e:
                print(prefix+'  qnames error', e)
            for sub in getattr(d,'dependencies',[]) or []:
                show_dep(sub, level+1)
        show_dep(dep)
        break
else:
    print('route not found')
