import ast, sys
p='tests/conftest.py'
with open(p,'r',encoding='utf-8') as f:
    src=f.read()
mod=ast.parse(src)
class YieldVisitor(ast.NodeVisitor):
    def __init__(self):
        self.count=0
    def visit_Yield(self,node):
        self.count+=1

for node in mod.body:
    if isinstance(node, ast.FunctionDef):
        vis=YieldVisitor()
        vis.visit(node)
        if vis.count>1:
            print(f"Function {node.name} has {vis.count} yield(s)")

# Also check nested functions
for node in ast.walk(mod):
    if isinstance(node, ast.FunctionDef):
        vis=YieldVisitor(); vis.visit(node)
        if vis.count>1:
            print(f"(walk) Function {node.name} has {vis.count} yield(s)")
