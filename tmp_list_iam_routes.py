import importlib, sys
mod = importlib.import_module('src.api.app')
app = getattr(mod, 'app')
print('app id', id(app))
paths = sorted([getattr(r,'path',None) for r in app.router.routes if getattr(r,'path',None) and r.path.startswith('/api/v1/iam')])
print('iam routes:', paths)
