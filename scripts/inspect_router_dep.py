import sys
from pathlib import Path
root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
from src.api.playbook_approval_endpoints import router as approval_router

for r in approval_router.routes:
    if getattr(r,'path','')=='/api/v1/playbook/request':
        print('route', r)
        dep = getattr(r,'dependant', None)
        print('dependant:', dep)
        if dep:
            print('body_params:', dep.body_params)
            print('body_fields:', getattr(dep,'body_fields', None))
            print('query_params:', dep.query_params)
            print('path_params:', dep.path_params)
            for p in dep.body_params:
                print('param name', p.name, 'type', p.annotation, 'required', p.required)
        break
