import sys, os
sys.path.insert(0, os.getcwd())
from src.api.playbook_approval_endpoints import router
for r in router.routes:
    print('PATH', r.path, 'NAME', r.name)
    try:
        dep = r.dependant
        bparams = getattr(dep, 'body_params', None)
        if bparams:
            print('  body params:')
            for bp in bparams:
                print('    ', bp.name, bp.annotation)
        else:
            print('  body params: none')
    except Exception as e:
        print('  error introspecting', e)
