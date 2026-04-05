import ast
import os

base = 'd:\\AI\\Threat_thy_sniffer\\src\\api'
res = []
for root, dirs, files in os.walk(base):
    for fn in files:
        if not fn.endswith('.py'):
            continue
        path = os.path.join(root, fn)
        try:
            with open(path, 'r', encoding='utf-8') as f:
                src = f.read()
            tree = ast.parse(src)
        except Exception as e:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                for arg in node.args.args:
                    if arg.arg == 'kwargs':
                        # check default for kwargs is represented differently; kwargs in args.args is a normal arg only if explicitly named
                        # in function signature, defaults align to the last len(defaults) args
                        has_default = False
                        # get index
                        idx = node.args.args.index(arg)
                        num_args = len(node.args.args)
                        num_defaults = len(node.args.defaults)
                        default_idx_start = num_args - num_defaults
                        if idx >= default_idx_start:
                            has_default = True
                        res.append((path, node.name, idx, has_default, ast.get_source_segment(src, node)))
            # also check async functions
            if isinstance(node, ast.AsyncFunctionDef):
                for arg in node.args.args:
                    if arg.arg == 'kwargs':
                        idx = node.args.args.index(arg)
                        num_args = len(node.args.args)
                        num_defaults = len(node.args.defaults)
                        default_idx_start = num_args - num_defaults
                        has_default = idx >= default_idx_start
                        res.append((path, node.name, idx, has_default, ast.get_source_segment(src, node)))

for path, name, idx, has_default, src in res:
    print(f"{path} - {name} - kwargs_index={idx} has_default={has_default}")
