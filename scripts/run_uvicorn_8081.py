import os
import sys
import uvicorn

# Ensure test helpers disabled and provide lightweight psycopg2 stub
os.environ['TEST_HELPERS_ENABLED'] = '0'
try:
    import types as _types
    if 'psycopg2' not in sys.modules:
        sys.modules['psycopg2'] = _types.ModuleType('psycopg2')
except Exception:
    pass

sys.path.insert(0, os.getcwd())
os.environ['PYTHONPATH'] = os.getcwd()

if __name__ == '__main__':
    uvicorn.run('src.api.app:app', host='127.0.0.1', port=8081, reload=False)
