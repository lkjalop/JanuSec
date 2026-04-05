from src.api.app import app
import inspect
for r in app.router.routes:
    if r.path == '/api/v1/endpoint/malware/analyze':
        print('Route found:', r.path, r.name)
        try:
            sig = inspect.signature(r.endpoint)
            print('Signature:', sig)
        except Exception as e:
            print('sig err', e)
        try:
            src = inspect.getsource(r.endpoint)
            print('\n'.join(src.splitlines()[:60]))
        except Exception as e:
            print('getsource err', e)
