import sys, pathlib, os
repo = pathlib.Path(__file__).resolve().parents[1]
if str(repo) not in sys.path:
    sys.path.insert(0, str(repo))
os.environ.setdefault('PLATFORM_LITE_INIT','1')
os.environ.setdefault('METRICS_DEBUG','1')
print('loading app...')
from src.api.app import app
from starlette.testclient import TestClient
print('app loaded, importing metrics_init...')
import importlib
mi = importlib.import_module('src.api.metrics_init')
print('metrics_init.REGISTRY=', getattr(mi,'REGISTRY',None))
print('metrics_init.generate_latest=', getattr(mi,'generate_latest', None))
try:
    from prometheus_client import generate_latest as gl
    print('prometheus_client.generate_latest=', gl)
except Exception as e:
    print('prometheus_client.generate_latest absent:', e)

client = TestClient(app)
r = client.get('/metrics')
print('status', r.status_code)
print('content (first 500):')
print(r.text[:500])
