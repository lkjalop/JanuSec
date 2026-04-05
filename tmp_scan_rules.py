import os
root='src/core/correlation/rules'
pyfiles=[]
for dirpath,dirs,files in os.walk(root):
    for f in files:
        if f.endswith('.py'):
            p=os.path.join(dirpath,f)
            try:
                size=os.path.getsize(p)
                with open(p,'r',encoding='utf-8',errors='ignore') as fh:
                    content=fh.read()
            except Exception:
                size=0
                content=''
            is_placeholder=('placeholder' in content.lower() or 'todo' in content.lower() or len(content.splitlines())<40)
            pyfiles.append({'path':p,'size':size,'lines':len(content.splitlines()),'placeholder':is_placeholder})
from collections import defaultdict
by_dir=defaultdict(lambda: {'count':0,'placeholder':0,'size':0})
for f in pyfiles:
    key=os.path.relpath(os.path.dirname(f['path']),root)
    by_dir[key]['count']+=1
    by_dir[key]['size']+=f['size']
    if f['placeholder']:
        by_dir[key]['placeholder']+=1
print('total_py',len(pyfiles))
for k,v in sorted(by_dir.items()):
    print(k, v)
print('\nTop 10 largest rule files:')
for f in sorted(pyfiles,key=lambda x:-x['size'])[:10]:
    print(f['path'], f['size'], f['lines'], 'PL' if f['placeholder'] else '')
