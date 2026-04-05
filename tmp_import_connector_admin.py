import importlib
try:
    m = importlib.import_module('src.api.connector_admin_endpoints')
    print('imported connector_admin_endpoints, router attr:', hasattr(m, 'router'))
except Exception as e:
    import traceback
    print('IMPORT ERROR:')
    traceback.print_exc()
