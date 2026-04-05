import os
import sys
import types
# Set lite/test env early
os.environ.setdefault('PLATFORM_LITE_INIT','1')
os.environ.setdefault('TEST_HELPERS_ENABLED','1')
os.environ.setdefault('DISABLE_DB','1')
# Pre-stub heavy modules that block import
for mod in ('scipy', 'scipy.stats', 'scipy.optimize', 'scipy._lib', 'numpy', 'pandas'):
    if mod not in sys.modules:
        sys.modules[mod] = types.ModuleType(mod)
# Stub the package-local modules that import heavy libs
stub = types.ModuleType('src.api.ab_analysis_endpoints')
stub.router = None
sys.modules['src.api.ab_analysis_endpoints'] = stub
stub2 = types.ModuleType('src.eval.ab_analysis')
# provide minimal symbols used by endpoints (if any)
sys.modules['src.eval.ab_analysis'] = stub2

# Now import app and list routes
from src.api.app import app
routes = sorted({getattr(r,'path',str(r)) for r in app.router.routes})
print('HAS /collectors/run:', '/collectors/run' in routes)
print('SAMPLE ROUTES (first 120):')
for p in routes[:120]:
    print(p)
