import sys
from pathlib import Path
root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
from fastapi.dependencies.utils import get_dependant
from src.api.playbook_approval_endpoints import request_playbook

dep = get_dependant(path='/', call=request_playbook)
print('body params:', dep.body_params)
for p in dep.body_params:
    print('param', p.name, p.annotation, p.required)
print('query params:', dep.query_params)
print('path params:', dep.path_params)
