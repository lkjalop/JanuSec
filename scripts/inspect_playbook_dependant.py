import sys
from pathlib import Path
p=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(p))
from fastapi.dependencies.utils import get_dependant
from src.api.app import app

for r in app.router.routes:
    if getattr(r,'path','')=='/api/v1/playbook/request' and 'POST' in getattr(r,'methods',[]):
        dep = get_dependant(path=r.path, call=r.endpoint)
        print('body_params:', [b.name for b in dep.body_params])
        print('query_params:', [q.name for q in dep.query_params])
        print('path_params:', [pa.name for pa in dep.path_params])
        print('header_params:', [h.name for h in dep.header_params])
        print('dependant:', dep)
        for d in dep.dependencies:
            print(' - dependency:', d.call, 'name', getattr(d.call,'__name__',None), 'required', d.required)
        break
else:
    print('route not found')
