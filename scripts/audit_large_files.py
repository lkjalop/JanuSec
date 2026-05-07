import re, collections, sys

def audit_file(path):
    with open(path, encoding='utf-8', errors='replace') as f:
        lines = f.readlines()
    
    routes = []
    route_pat = re.compile(r'@(?:app|router)\.(get|post|put|delete|patch|websocket)\s*\(')
    for i, line in enumerate(lines):
        m = route_pat.search(line)
        if m:
            path_m = re.search(r'[\'](/[^\']+)', line)
            path_str = path_m.group(1) if path_m else line.strip()
            method = m.group(1).upper()
            routes.append((i+1, method, path_str))
    
    dup_paths = [p for p, cnt in collections.Counter(p for _, _, p in routes).items() if cnt > 1]
    
    # Functions over 100 lines (top-level)
    big_fns = []
    fn_start = None
    fn_name = None
    for i, line in enumerate(lines):
        m = re.match(r'^(async def|def) (\w+)', line)
        if m:
            if fn_start is not None:
                length = i - fn_start
                if length > 100:
                    big_fns.append((fn_name, fn_start+1, i, length))
            fn_name = m.group(2)
            fn_start = i
    if fn_start is not None:
        length = len(lines) - fn_start
        if length > 100:
            big_fns.append((fn_name, fn_start+1, len(lines), length))
    
    return len(lines), routes, dup_paths, big_fns

files = [
    'src/api/app.py',
    'src/api/deep_analyze_endpoints.py',
    'src/api/server.py',
    'src/api/graph_sessions.py',
    'src/api/tier2_canvas_endpoints.py',
    'src/analysis/offline_workbook_assessment.py',
]

for path in files:
    nlines, routes, dups, big_fns = audit_file(path)
    print(f'--- {path} ({nlines} lines) ---')
    print(f'  Routes: {len(routes)}, Dups: {len(dups)}')
    if dups:
        for d in dups:
            print(f'    DUP: {d}')
    print(f'  Large functions (>100 lines): {len(big_fns)}')
    for fn, start, end, length in sorted(big_fns, key=lambda x: -x[3])[:6]:
        print(f'    {fn}() L{start}-{end} ({length} lines)')
    # Route prefix groups
    if routes:
        grps = collections.Counter()
        for _, method, p in routes:
            parts = p.strip('/').split('/')
            prefix = '/'.join(parts[:3]) if len(parts)>=3 else p
            grps[prefix] += 1
        print(f'  Route groups (top-10):')
        for prefix, cnt in grps.most_common(10):
            print(f'    /{prefix}: {cnt}')
    print()
