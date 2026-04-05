import importlib, traceback
try:
    m = importlib.import_module('src.api.supply_chain_endpoints')
    print('import ok', m)
except Exception as e:
    print('import failed')
    traceback.print_exc()
