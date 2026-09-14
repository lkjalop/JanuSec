import importlib
mod = importlib.import_module('src.api.app')
app = mod.app
for r in app.router.routes:
    try:
        p = getattr(r,'path',None)
        if p and p == '/api/v1/config/assessment_defaults':
            print('FOUND PATH:', p)
            print('methods:', getattr(r,'methods',None))
            print('endpoint:', getattr(r,'endpoint',None))
            print('name:', getattr(r,'name',None))
            print('repr:', r)
    except Exception as e:
        print('err', e)

for r in app.router.routes:
    try:
        p = getattr(r,'path',None)
        if p and p == '/api/v1/assessments/save_metadata':
            print('FOUND PATH2:', p)
            print('methods:', getattr(r,'methods',None))
            print('endpoint:', getattr(r,'endpoint',None))
            print('name:', getattr(r,'name',None))
            print('repr:', r)
    except Exception as e:
        print('err', e)
