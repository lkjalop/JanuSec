import importlib
m = importlib.import_module('src.api.app')
print('has _lite_emit_factor', hasattr(m,'_lite_emit_factor'))
print('func', getattr(m,'_lite_emit_factor',None))
for r in m.app.router.routes:
    if getattr(r,'path',None)=='/api/v1/events':
        h=getattr(r,'endpoint',None)
        print('handler module', h.__module__)
        print('_lite_emit_factor in handler globals?', '_lite_emit_factor' in h.__globals__)
        print('handler global', h.__globals__.get('_lite_emit_factor'))
        break
