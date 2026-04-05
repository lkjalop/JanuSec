import os
import uvicorn

# Ensure test helpers disabled
os.environ['TEST_HELPERS_ENABLED'] = '0'
# Provide lightweight stub for optional DB drivers to avoid import-time failures
try:
    import types as _types
    import sys as _sys
    if 'psycopg2' not in _sys.modules:
        _sys.modules['psycopg2'] = _types.ModuleType('psycopg2')
except Exception:
    pass
import sys
sys.path.insert(0, os.getcwd())
os.environ['PYTHONPATH'] = os.getcwd()

if __name__ == '__main__':
    uvicorn.run('src.api.app:app', host='0.0.0.0', port=8080, reload=False)
