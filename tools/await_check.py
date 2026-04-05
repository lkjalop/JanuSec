import ast, sys
p='src/api/server.py'
with open(p, 'r', encoding='utf-8') as f:
    src = f.read()
try:
    tree = ast.parse(src, p)
except SyntaxError as e:
    print('SyntaxError', e)
    lines = src.splitlines()
    for i in range(max(0,e.lineno-5), min(len(lines), e.lineno+5)):
        print(f"{i+1}: {lines[i]}")
    sys.exit(1)
class Finder(ast.NodeVisitor):
    def __init__(self):
        self.issues=[]
    def visit_Await(self, node):
        self.issues.append((node.lineno, node.col_offset))
        self.generic_visit(node)
finder=Finder()
finder.visit(tree)
print('Await nodes at:', finder.issues)
await_lines = {ln for ln,_ in finder.issues}
async_funcs=[]
for node in ast.walk(tree):
    if isinstance(node, ast.AsyncFunctionDef):
        start = node.lineno
        end = max(getattr(n,'lineno', start) for n in ast.walk(node))
        async_funcs.append((start,end,node.name))
print('Async functions (sample):', async_funcs[:10])
for ln in sorted(await_lines):
    ok=False
    for s,e,nm in async_funcs:
        if s<=ln<=e:
            ok=True
            break
    if not ok:
        print('Await outside async fn at line', ln)
