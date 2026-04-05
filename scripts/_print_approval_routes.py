import sys, os
sys.path.insert(0, os.getcwd())
from src.api.playbook_approval_endpoints import router
for r in router.routes:
    print('PATH', getattr(r,'path',None), 'NAME', getattr(r,'name',None))
    try:
        print('  methods', r.methods)
    except Exception:
        pass
