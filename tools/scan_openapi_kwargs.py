import os
os.environ.setdefault('PYTEST_CURRENT_TEST','1')
from src.api.app import app
import json, sys, traceback

try:
    spec = app.openapi()
except Exception as e:
    print('openapi() failed:', e)
    traceback.print_exc()
    sys.exit(1)

found = []
for path, ops in (spec.get('paths') or {}).items():
    for method, op in (ops or {}).items():
        params = op.get('parameters') or []
        for p in params:
            if p.get('name') == 'kwargs':
                found.append((path, method.upper(), p.get('required', False)))

if not found:
    print('No kwargs parameters in OpenAPI')
else:
    for path, method, req in found:
        print(f"{path} {method} required={req}")
