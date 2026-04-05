import os
import sys
# Ensure repo root on path
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
os.environ['TEST_HELPERS_ENABLED'] = '1'
os.environ['FAST_TEST_MODE'] = '1'
# Run uvicorn programmatically to avoid shell quoting issues
try:
    import uvicorn
    uvicorn.run('src.api.app:app', host='127.0.0.1', port=8080, log_level='warning')
except Exception as e:
    print('ERR', e)
    raise
