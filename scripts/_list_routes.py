import os
os.environ.setdefault('PLATFORM_LITE_INIT','1')
os.environ.setdefault('TEST_HELPERS_ENABLED','1')
os.environ.setdefault('DISABLE_DB','1')
from src.api.app import app
routes = sorted({getattr(r,'path',str(r)) for r in app.router.routes})
print('HAS SBOM UPLOAD:', '/api/v1/sbom/upload' in routes)
print('HAS SCANNER SYFT TRIGGER:', '/api/v1/scanners/syft/trigger' in routes)
print('SAMPLE ROUTES (first 80):')
for p in routes[:80]:
    print(p)
