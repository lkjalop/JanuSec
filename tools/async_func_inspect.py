import ast
p='src/api/server.py'
src=open(p,'r',encoding='utf-8').read()
try:
    tree=ast.parse(src,p)
except Exception as e:
    print('parse failed', e)
    raise
for node in ast.walk(tree):
    if isinstance(node, ast.AsyncFunctionDef) and node.name=='_process_endpoint_event':
        start=node.lineno
        end=max(getattr(n,'lineno',start) for n in ast.walk(node))
        print('_process_endpoint_event start', start, 'end', end)
        break
else:
    print('not found')
