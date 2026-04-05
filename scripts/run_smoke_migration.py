#!/usr/bin/env python3
"""Run Alembic upgrade head programmatically and validate the oauth_tokens table.

Usage: python scripts/run_smoke_migration.py --db sqlite:///./data/test.db
"""
import os
import sys
import argparse
import sqlite3

def run_alembic(db_url, repo_root=None):
    try:
        from alembic.config import Config
        from alembic import command as alembic_command
    except Exception as e:
        print('alembic not installed:', e)
        raise
    if repo_root is None:
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    ini_path = os.path.join(repo_root, 'alembic.ini')
    cfg = Config(ini_path)
    cfg.set_main_option('sqlalchemy.url', db_url)
    print('Running alembic upgrade head against', db_url)
    alembic_command.upgrade(cfg, 'head')

def verify_sqlite(db_path):
    exists = os.path.exists(db_path)
    print('DB file exists:', exists, db_path)
    if not exists:
        return False
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='oauth_tokens'")
    found = cur.fetchone() is not None
    print('oauth_tokens table present:', found)
    if found:
        print('Table schema:')
        for r in cur.execute("PRAGMA table_info('oauth_tokens')"):
            print(r)
    conn.close()
    return found


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--db', default=os.environ.get('APP_DB_DSN', 'sqlite:///./data/test_local_migrations.db'))
    args = p.parse_args()
    db = args.db
    if db.startswith('sqlite:///'):
        db_path = db.replace('sqlite:///', '')
    else:
        db_path = None
    try:
        run_alembic(db)
    except Exception as e:
        print('Alembic run failed:', e)
        sys.exit(2)
    if db_path:
        ok = verify_sqlite(db_path)
        if not ok:
            print('Verification failed')
            sys.exit(3)
    print('Smoke migration completed successfully')

if __name__ == '__main__':
    main()
