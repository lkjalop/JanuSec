import sys
import json

# Ensure repo root is on sys.path
if __name__ == '__main__':
    sys.path.insert(0, '.')
    try:
        from src.api.app import create_app
    except Exception as e:
        print('FAILED_IMPORT_APP', repr(e))
        raise
    try:
        app = create_app()
    except Exception as e:
        print('FAILED_CREATE_APP', repr(e))
        raise
    routes = sorted({getattr(r, 'path', str(r)) for r in app.router.routes})
    print('ROUTES_COUNT:', len(routes))
    for p in routes:
        print(p)
    print('\nHAS_DEEP_ANALYZE:', '/api/v1/assessments/deep_analyze' in routes)
    # also check report path
    print('HAS_DEEP_REPORT:', any(p.startswith('/api/v1/assessments/report') for p in routes))
