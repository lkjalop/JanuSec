#!/usr/bin/env python3
"""Simple wrapper to run Alembic migrations with dry-run/force/rollback support.

Usage:
  python scripts/db_migrate.py --dry-run
  python scripts/db_migrate.py --apply
  python scripts/db_migrate.py --rollback

This wrapper loads `alembic.ini` from the repository root.
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import Optional

from alembic.config import Config
from alembic import command


def load_config() -> Config:
    here = os.path.abspath(os.path.dirname(__file__) + os.path.sep + '..')
    ini_path = os.path.join(here, 'alembic.ini')
    if not os.path.exists(ini_path):
        print('alembic.ini not found at', ini_path, file=sys.stderr)
        sys.exit(2)
    cfg = Config(ini_path)
    # allow DATABASE_URL override
    db = os.environ.get('DATABASE_URL')
    if db:
        cfg.set_main_option('sqlalchemy.url', db)
    return cfg


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser()
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument('--dry-run', action='store_true', help='Print SQL that would be run')
    g.add_argument('--apply', action='store_true', help='Apply migrations')
    g.add_argument('--rollback', action='store_true', help='Rollback last migration')
    p.add_argument('--rev', default='head', help='Target revision (default: head)')
    args = p.parse_args(argv)

    cfg = load_config()

    if args.dry_run:
        # produce SQL for the upgrade
        print('Generating SQL for upgrade ->', args.rev)
        command.upgrade(cfg, args.rev, sql=True)
        return 0

    if args.apply:
        print('Applying migrations ->', args.rev)
        command.upgrade(cfg, args.rev)
        return 0

    if args.rollback:
        print('Rolling back one revision')
        # downgrade one step (this assumes linear history)
        command.downgrade(cfg, '-1')
        return 0

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
