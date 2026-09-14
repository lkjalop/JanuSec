"""Simple RBAC CLI for managing roles (assign, revoke, list).

Usage:
  python scripts/rbac_manage.py list
  python scripts/rbac_manage.py assign <api_key> <role>
  python scripts/rbac_manage.py revoke <api_key> <role>

This uses `src.security.rbac` helpers and writes to `data/roles.json`.
"""
from __future__ import annotations
import sys
import os
import argparse

# Ensure repository root is importable so `from src.security import rbac` works
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_THIS_DIR)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

def main(argv=None):
    parser = argparse.ArgumentParser(description='Manage RBAC roles')
    sub = parser.add_subparsers(dest='cmd')
    sub.required = True

    p_list = sub.add_parser('list', help='List all roles')

    p_assign = sub.add_parser('assign', help='Assign a role to an api key')
    p_assign.add_argument('api_key')
    p_assign.add_argument('role')

    p_revoke = sub.add_parser('revoke', help='Revoke a role from an api key')
    p_revoke.add_argument('api_key')
    p_revoke.add_argument('role')

    args = parser.parse_args(argv)

    try:
        from src.security import rbac
    except Exception as exc:
        print('Failed to import RBAC module:', exc)
        return 2

    if args.cmd == 'list':
        # Print JSON-ish view
        rows = {}
        try:
            # Access internal map for convenience
            raw = getattr(rbac, '_ROLE_MAP', None)
            if raw is None:
                print('{}')
                return 0
            for k, v in raw.items():
                rows[k] = sorted(list(v))
        except Exception:
            rows = {}
        import json
        print(json.dumps({'roles': rows}, indent=2))
        return 0

    if args.cmd == 'assign':
        rbac.assign_role(args.api_key, args.role)
        print('OK')
        return 0

    if args.cmd == 'revoke':
        try:
            rbac.revoke_role(args.api_key, args.role)
            print('OK')
            return 0
        except Exception as exc:
            print('Failed:', exc)
            return 2

if __name__ == '__main__':
    raise SystemExit(main())