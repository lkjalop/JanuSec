import os, sys
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
print('PYTHONPATH set to', sys.path[0])
try:
    import importlib
    m = importlib.import_module('src.api.app')
    print('Imported src.api.app OK')
except Exception as e:
    import traceback
    traceback.print_exc()
    print('IMPORT_ERROR:', e)
