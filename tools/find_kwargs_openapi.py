import os,json
os.environ['PYTEST_CURRENT_TEST']='1'
from src.api.app import app
ops = app.openapi().get('paths',{})
found = []
for path,pdict in ops.items():
    for method,op in pdict.items():
        for param in op.get('parameters',[]):
            if param.get('name')=='kwargs':
                found.append((path,method,param.get('in'), param.get('required')))
print('FOUND', found)
