"""Lightweight migration runner.

Usage (PowerShell):
  $env:APP_DB_DSN='postgresql://user:pass@localhost:5432/threatsifter'
  python scripts/run_migrations.py

Applies migrations in lexicographic order once. Creates a migrations table
for tracking applied versions.
"""
import os
import asyncio
import logging
from pathlib import Path
import argparse

try:
    import asyncpg
except Exception as e:  # pragma: no cover
    raise SystemExit("asyncpg required to run migrations")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("migrations")

MIGRATIONS_DIR = Path(__file__).parent.parent / 'migrations'

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ DEFAULT NOW()
);
"""

CHECK_VERSION = "SELECT 1 FROM schema_migrations WHERE version=$1"
INSERT_VERSION = "INSERT INTO schema_migrations (version) VALUES ($1)"

async def apply_migration(conn, version: str, sql: str):
    exists = await conn.fetchrow(CHECK_VERSION, version)
    if exists:
        logger.info(f"Skipping already applied migration {version}")
        return
    logger.info(f"Applying migration {version}")
    async with conn.transaction():
        await conn.execute(sql)
        await conn.execute(INSERT_VERSION, version)
    logger.info(f"Applied migration {version}")

async def run(dry_run: bool = False):
    dsn = os.getenv('APP_DB_DSN')
    if not dsn:
        host = os.getenv('DB_HOST', 'localhost')
        port = os.getenv('DB_PORT', '5432')
        user = os.getenv('DB_USER', 'postgres')
        password = os.getenv('DB_PASSWORD', 'postgres')
        database = os.getenv('DB_NAME', 'threatsifter')
        dsn = f"postgresql://{user}:{password}@{host}:{port}/{database}"
    conn = await asyncpg.connect(dsn=dsn)
    try:
        await conn.execute(CREATE_TABLE)
        for path in sorted(MIGRATIONS_DIR.glob('*.sql')):
            sql = path.read_text()
            # Evaluate whether applied
            exists = await conn.fetchrow(CHECK_VERSION, path.name)
            if exists:
                logger.info(f"Skipping already applied migration {path.name}")
                continue
            if dry_run:
                logger.info(f"[DRY-RUN] Would apply migration {path.name}")
            else:
                await apply_migration(conn, path.name, sql)
    finally:
        await conn.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run database migrations')
    parser.add_argument('--dry-run', action='store_true', help='List unapplied migrations without executing')
    args = parser.parse_args()
    asyncio.run(run(dry_run=args.dry_run))
