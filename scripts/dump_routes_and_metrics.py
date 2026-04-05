import os
import sys
from pprint import pprint

# Ensure repo root on path so `src` package resolves
sys.path.insert(0, str(os.getcwd()))
os.environ['PLATFORM_LITE_INIT'] = os.environ.get('PLATFORM_LITE_INIT', '1')

def main():
    try:
        from src.api.app import create_app
    except Exception as e:
        print('create_app import failed:', e)
        return
    app = create_app()
    routes = []
    for r in app.router.routes:
        try:
            routes.append({'path': getattr(r, 'path', str(r)), 'name': getattr(r, 'name', None), 'methods': getattr(r, 'methods', None)})
        except Exception:
            routes.append({'repr': repr(r)})
    print(f'ROUTES_COUNT: {len(routes)}')
    # show routes that look like /api/v1/
    api_routes = [r for r in routes if isinstance(r.get('path'), str) and r['path'].startswith('/api/')]
    print('API routes sample (first 50):')
    pprint(api_routes[:50])

    # Test /metrics
    try:
        from starlette.testclient import TestClient
        client = TestClient(app)
        r = client.get('/metrics')
        print('/metrics status:', r.status_code)
        print('/metrics text head:', (r.text or '')[:200])
    except Exception as e:
        print('metrics check failed:', e)


if __name__ == '__main__':
    main()
