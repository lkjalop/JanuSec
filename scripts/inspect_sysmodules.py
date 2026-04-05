import importlib, sys, os
# Simulate pytest collection by importing tests.conftest
try:
    cf = importlib.import_module('tests.conftest')
    print('Imported tests.conftest')
except Exception as e:
    print('conftest import failed:', e)

print('botocore in sys.modules?')
for k in sorted([k for k in sys.modules.keys() if 'botocore' in k]):
    print(k, '->', getattr(sys.modules[k], '__file__', None))

try:
    import botocore
    print('botocore file:', getattr(botocore, '__file__', None))
except Exception as e:
    print('botocore import error:', e)
