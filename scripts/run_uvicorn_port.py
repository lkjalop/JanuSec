import os
import sys
import uvicorn

# Configure environment for test-friendly startup
os.environ.setdefault('TEST_HELPERS_ENABLED', '0')
try:
    import types as _types
    if 'psycopg2' not in sys.modules:
        sys.modules['psycopg2'] = _types.ModuleType('psycopg2')
except Exception:
    pass

sys.path.insert(0, os.getcwd())
os.environ.setdefault('PYTHONPATH', os.getcwd())

def main():
    port = int(os.environ.get('RUN_PORT', os.environ.get('PORT', '18081')))
    host = os.environ.get('RUN_HOST', '127.0.0.1')
    uvicorn.run('src.api.app:app', host=host, port=port, reload=False)

if __name__ == '__main__':
    main()
