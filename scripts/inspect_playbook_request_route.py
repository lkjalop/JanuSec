import sys
from pathlib import Path
root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
from src.api.app import app
import inspect

found = False
for r in app.router.routes:
    if getattr(r, 'path', None) == '/api/v1/playbook/request' and 'POST' in getattr(r, 'methods', []):
        found = True
        print('Route:', r.path, 'methods:', r.methods, 'name:', getattr(r, 'name', None))
        ep = getattr(r, 'endpoint', None)
        print('Endpoint repr:', repr(ep))
        print('Callable name:', getattr(ep, '__name__', None))
        try:
            sig = inspect.signature(ep)
            print('Signature:', sig)
        except Exception as e:
            print('signature err', e)
        # unwrap chain
        w = ep
        depth = 0
        while w and depth < 8:
            print('\nwrapper depth', depth)
            print(' type:', type(w))
            print(' __name__:', getattr(w,'__name__',None))
            print(' __qualname__:', getattr(w,'__qualname__',None))
            print(' __wrapped__:', getattr(w,'__wrapped__',None))
            print(' __signature__:', getattr(w,'__signature__',None))
            try:
                print(' source head:', '\n'.join(inspect.getsource(w).splitlines()[:10]))
            except Exception:
                pass
            w = getattr(w, '__wrapped__', None)
            depth += 1
        break
if not found:
    print('playbook request route not found')
