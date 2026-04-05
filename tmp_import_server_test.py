import importlib, traceback
try:
    importlib.import_module('src.api.server')
    print('imported ok')
except Exception as e:
    traceback.print_exc()
