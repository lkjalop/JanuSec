import os
os.environ['PLATFORM_LITE_INIT'] = '1'
os.environ['TEST_HELPERS_ENABLED'] = '1'
os.environ['DISABLE_DB'] = '1'

from src.api.app import app
routes = [getattr(r, 'path', '') for r in app.router.routes]
v1_conn = [p for p in routes if p.startswith('/api/v1/connectors')]
print('V1 CONNECTORS:', v1_conn[:10])

# manual include test
try:
    from src.api.routes import connectors as _connectors_ctrl
    print('router prefix:', _connectors_ctrl.router.prefix)
    print('router routes:', [r.path for r in _connectors_ctrl.router.routes][:4])
    try:
        app.include_router(_connectors_ctrl.router)
        print('include succeeded')
    except Exception as e:
        import traceback; traceback.print_exc()
except Exception as e:
    import traceback; traceback.print_exc()

routes2 = [getattr(r, 'path', '') for r in app.router.routes]
v1_conn2 = [p for p in routes2 if p.startswith('/api/v1/connectors')]
print('V1 CONNECTORS after manual include:', v1_conn2[:10])
