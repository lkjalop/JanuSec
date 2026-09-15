import os
os.environ['PYTEST_CURRENT_TEST'] = '1'
os.environ['TEST_HELPERS_ENABLED'] = '1'
from src.api.server import app
import json
p = '/api/v1/graph/reconstruct'
openapi = app.openapi()
paths = openapi.get('paths', {})
print('Has path:', p in paths)
if p in paths:
    op = paths[p].get('post') or paths[p].get('get')
    print('Parameters:')
    for param in (op.get('parameters') or []):
        print(' -', param.get('name'), param.get('in'), param.get('required'))
    print('\nRequestBody present:', 'requestBody' in op)
    if 'requestBody' in op:
        print('content types:', list(op['requestBody'].get('content', {}).keys()))

# Also check top-level components for any schema named kwargs
for pname,p in paths.items():
    for method,op in p.items():
        for param in (op.get('parameters') or []):
            if param.get('name')=='kwargs':
                print('\nFOUND kwargs param on path', pname, 'method', method)
print('done')
