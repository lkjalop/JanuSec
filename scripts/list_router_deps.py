import sys
from pathlib import Path
root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
from src.api.playbook_approval_endpoints import router as approval_router

for r in approval_router.routes:
    print('ROUTE', r.path, r.methods, 'name', getattr(r,'name',None))
    dep = getattr(r,'dependant', None)
    if dep:
        print('  body_params:', dep.body_params)
        for bp in dep.body_params:
            print('   -', bp.name, bp.annotation, bp.required)
    else:
        print('  no dependant')
    print()
