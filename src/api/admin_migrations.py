"""Admin DB migration trigger endpoint.

This endpoint is intentionally small: it validates RBAC and then runs the
migration runner as a subprocess. It is gated behind the
ADMIN_TRIGGER_MIGRATIONS environment flag to avoid accidental runs.
"""
import os
import subprocess
import shlex
import json
import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status

from ..auth import auth_dependency, require_admin  # project auth helpers
from src.security.roles import require_roles

try:
    import psycopg2
    from psycopg2.extras import Json
except Exception:
    psycopg2 = None  # DB audit will be best-effort

router = APIRouter(prefix="/api/v1/admin/db", tags=["admin"], dependencies=[Depends(require_roles('admin'))])


def migrations_enabled() -> bool:
    return os.getenv('ADMIN_TRIGGER_MIGRATIONS', '0') in ('1', 'true', 'yes')


@router.post('/migrate')
def trigger_migrations(payload: dict, user=Depends(auth_dependency)):
    if not migrations_enabled():
        raise HTTPException(status_code=403, detail='Migrations are disabled on this instance')
    # require admin role
    if not require_admin(user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='admin role required')

    # minimal payload validation
    confirm = payload.get('confirm')
    if confirm is not True and confirm != 'yes':
        raise HTTPException(status_code=422, detail='must include {"confirm":true} to run')

    # Build command (Alembic-only)
    script = os.path.join(os.path.dirname(__file__), '..', '..', 'scripts', 'run_smoke_migration.py')
    dsn = os.getenv('APP_DB_DSN')
    if not dsn:
        host = os.getenv('DB_HOST', 'localhost')
        port = os.getenv('DB_PORT', '5432')
        user_env = os.getenv('DB_USER', 'postgres')
        password = os.getenv('DB_PASSWORD', 'postgres')
        database = os.getenv('DB_NAME', 'janusec')
        dsn = f"postgresql://{user_env}:{password}@{host}:{port}/{database}"
    cmd = f"python {shlex.quote(script)} --db {shlex.quote(dsn)}"
    # Best-effort write an audit row before running
    audit_id: Optional[int] = None
    conn = None
    try:
        if psycopg2:
            dsn = os.getenv('APP_DB_DSN')
            if not dsn:
                host = os.getenv('DB_HOST', 'localhost')
                port = os.getenv('DB_PORT', '5432')
                user = os.getenv('DB_USER', 'postgres')
                password = os.getenv('DB_PASSWORD', 'postgres')
                database = os.getenv('DB_NAME', 'janusec')
                dsn = f"postgresql://{user}:{password}@{host}:{port}/{database}"
            conn = psycopg2.connect(dsn)
            cur = conn.cursor()
            env_snapshot = {k: os.getenv(k) for k in ['APP_DB_DSN','DB_HOST','DB_PORT','DB_USER','DB_NAME']}
            cur.execute(
                "INSERT INTO migration_audit (invoked_by, env_snapshot, status) VALUES (%s, %s, %s) RETURNING id",
                (getattr(user, 'sub', str(user)), Json(env_snapshot), 'started')
            )
            audit_id = cur.fetchone()[0]
            conn.commit()
    except Exception:
        # Swallow DB audit errors; do not block migrations
        try:
            if conn:
                conn.close()
        except Exception:
            pass
        conn = None

    try:
        proc = subprocess.run(cmd, shell=True, check=False, capture_output=True, text=True, timeout=300)
    except Exception as e:
        # ensure we attempt to update audit record with failure
        if conn is None and psycopg2:
            try:
                conn = psycopg2.connect(os.getenv('APP_DB_DSN') or '')
            except Exception:
                conn = None
        if conn and audit_id:
            try:
                cur = conn.cursor()
                cur.execute(
                    "UPDATE migration_audit SET finished_at=%s, status=%s, exit_code=%s, stderr=%s WHERE id=%s",
                    (datetime.datetime.utcnow(), 'failed', -1, str(e), audit_id)
                )
                conn.commit()
            except Exception:
                pass
        raise HTTPException(status_code=500, detail=str(e))

    # Update audit record with results (best-effort)
    try:
        if psycopg2 and audit_id:
            if conn is None:
                dsn = os.getenv('APP_DB_DSN')
                if not dsn:
                    host = os.getenv('DB_HOST', 'localhost')
                    port = os.getenv('DB_PORT', '5432')
                    user = os.getenv('DB_USER', 'postgres')
                    password = os.getenv('DB_PASSWORD', 'postgres')
                    database = os.getenv('DB_NAME', 'janusec')
                    dsn = f"postgresql://{user}:{password}@{host}:{port}/{database}"
                conn = psycopg2.connect(dsn)
            cur = conn.cursor()
            cur.execute(
                "UPDATE migration_audit SET finished_at=%s, status=%s, exit_code=%s, stdout=%s, stderr=%s WHERE id=%s",
                (
                    datetime.datetime.utcnow(),
                    'success' if proc.returncode == 0 else 'failed',
                    proc.returncode,
                    proc.stdout,
                    proc.stderr,
                    audit_id,
                ),
            )
            conn.commit()
    except Exception:
        pass
    finally:
        try:
            if conn:
                conn.close()
        except Exception:
            pass

    if proc.returncode != 0:
        raise HTTPException(status_code=500, detail=f'Migration runner failed: {proc.stderr or proc.stdout}')

    return {'ok': True, 'output': proc.stdout}
