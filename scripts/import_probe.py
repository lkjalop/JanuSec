import importlib, traceback, sys, os

# Ensure repo root is on sys.path so "src" package is importable like Uvicorn
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

mod = 'src.api.deep_analyze_endpoints'
try:
    importlib.invalidate_caches()
    importlib.import_module(mod)
    print('IMPORT_OK')
except Exception as e:
    print('IMPORT_FAILED:', repr(e))
    traceback.print_exc()
