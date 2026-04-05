"""Repository migration helpers: call into repositories.decisions_repo if it exposes migration helpers."""
import logging

logger = logging.getLogger(__name__)


def run_repo_migrations():
    try:
        import repositories.decisions_repo as dr
        run = getattr(dr, 'run_migrations', None)
        if run:
            try:
                run()
            except Exception:
                logger.exception('repositories.decisions_repo.run_migrations failed')
    except Exception:
        logger.debug('No upstream repositories.decisions_repo migration helper found')
    # Ensure IAM cursor table exists if DB is available
    try:
        from src.db.migrations_iam import ensure_iam_cursors_table
        ensure_iam_cursors_table()
        logger.info('Ensured IAM cursors table exists')
    except Exception as exc:
        logger.debug('Failed to ensure IAM cursors table: %s', exc)
    # Attempt to create incidents table if our incidents_repo exposes the SQL constant
    try:
        import src.repositories.incidents_repo as ir
        from db.database import execute, with_retry
        sql = getattr(ir, 'CREATE_INCIDENTS_TABLE', None)
        if sql and execute and with_retry:
            async def _do():
                await execute(sql)
            try:
                import asyncio
                asyncio.get_event_loop().run_until_complete(_do())
                logger.info('Ensured incidents table exists')
            except Exception as exc:
                logger.debug('Failed to ensure incidents table: %s', exc)
    except Exception:
        logger.debug('No incidents_repo migration helper found or DB unavailable')
