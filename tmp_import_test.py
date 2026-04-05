import importlib, traceback
try:
    m = importlib.import_module('src.api.decisions_stream')
    print('OK', hasattr(m, 'router'))
except Exception:
    traceback.print_exc()
