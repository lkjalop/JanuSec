from __future__ import annotations

import csv
import os
import sys

def load_routes():
    # Import FastAPI app without running heavy init in lite mode
    os.environ.setdefault('PLATFORM_LITE_INIT','1')
    from src.api.app import app  # type: ignore
    routes = set()
    for r in app.routes:
        try:
            path = getattr(r, 'path')
            methods = getattr(r, 'methods', {'GET'})
            if not isinstance(methods, (set, list, tuple)):
                continue
            if not isinstance(path, str) or not path.startswith('/api'):
                continue
            for m in methods:
                routes.add((path, m.upper()))
        except Exception:
            continue
    return routes

def load_allowlist(csv_path: str):
    allowed = set()
    with open(csv_path, 'r', encoding='utf-8') as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            p = (row.get('path') or '').strip()
            m = (row.get('method') or '').strip().upper()
            if p and m:
                allowed.add((p, m))
    return allowed

def main():
    root = os.path.dirname(os.path.dirname(__file__))
    csv_path = os.path.join(root, 'security', 'api_endpoint_allowlist.csv')
    if not os.path.exists(csv_path):
        print('allowlist missing at', csv_path)
        return 0
    routes = load_routes()
    allowed = load_allowlist(csv_path)
    extras = sorted([f"{p} {m}" for (p,m) in routes if (p,m) not in allowed])
    if extras:
        print('Routes not in allowlist:')
        for e in extras:
            print('  ', e)
    enforce = os.getenv('ROUTE_ALLOWLIST_ENFORCE','0').lower() in {'1','true','yes'}
    return 1 if (extras and enforce) else 0

if __name__ == '__main__':
    sys.exit(main())

