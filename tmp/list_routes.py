import importlib, sys
mod = importlib.import_module('src.api.app')
app = getattr(mod, 'app')
paths = sorted({getattr(r,'path',None) for r in app.router.routes if getattr(r,'path',None)})
for p in paths:
    if p and p.startswith('/api/v1'):
        print(p)
print('---')
for p in paths:
    if p and ('config' in p or 'assessments' in p):
        print(p)
