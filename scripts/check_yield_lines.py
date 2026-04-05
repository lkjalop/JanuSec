import ast
p='tests/conftest.py'
src=open(p,'r',encoding='utf-8').read()
mod=ast.parse(src)
for node in mod.body:
    if isinstance(node, ast.FunctionDef) and node.name=='_stub_external_http':
        for n in ast.walk(node):
            if isinstance(n, ast.Yield):
                print('Yield at line', n.lineno)
