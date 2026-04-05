from __future__ import annotations
import asyncio
import os
import logging
import subprocess
from typing import Optional

logger = logging.getLogger(__name__)
_migration_lock = asyncio.Lock()
_migrations_applied = False


async def _apply_alembic(db_url: Optional[str] = None) -> None:
    """Apply Alembic migrations via CLI and fail on real errors."""
    global _migrations_applied
    async with _migration_lock:
        if _migrations_applied:
            return
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
        alembic_cfg_path = os.path.join(repo_root, 'alembic.ini')
        if not os.path.exists(alembic_cfg_path):
            raise RuntimeError(f'alembic_config_missing:{alembic_cfg_path}')
        env = os.environ.copy()
        env['PYTHONPATH'] = repo_root + (os.pathsep + env['PYTHONPATH'] if env.get('PYTHONPATH') else '')
        env['DATABASE_URL'] = db_url or env.get('APP_DB_DSN') or env.get('DATABASE_URL', '')
        cmd = [env.get('ALEMBIC_CMD', 'alembic'), '-c', alembic_cfg_path, 'upgrade', 'head']
        logger.info('Applying Alembic migrations to head')
        result = await asyncio.to_thread(
            subprocess.run,
            cmd,
            cwd=repo_root,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or '').strip()
            raise RuntimeError(f'alembic_upgrade_failed:{detail or result.returncode}')
        _migrations_applied = True
        logger.info('Alembic migrations applied successfully')


async def apply_migrations_postgres(pool):  # asyncpg pool
    db_url = os.environ.get('APP_DB_DSN') or os.environ.get('DATABASE_URL')
    await _apply_alembic(db_url)


async def apply_migrations_sqlite(connection):
    db_url = os.environ.get('APP_DB_DSN') or os.environ.get('DATABASE_URL')
    if not db_url:
        logger.info('SQLite migrations skipped: APP_DB_DSN/DATABASE_URL not set')
        return
    await _apply_alembic(db_url)


__all__ = ['apply_migrations_postgres', 'apply_migrations_sqlite']
