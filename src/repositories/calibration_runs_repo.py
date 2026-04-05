from __future__ import annotations
import os
import json
from typing import Any, Dict

FILE = os.getenv('CALIBRATION_RUNS_FILE', 'data/calibration_runs.json')


def _ensure_file():
    p = os.path.abspath(FILE)
    d = os.path.dirname(p)
    try:
        os.makedirs(d, exist_ok=True)
    except Exception:
        pass
    return p


def persist_run(run_payload: Dict[str, Any]) -> bool:
    """Persist a calibration run result to disk (append-only) or to DB in future.

    Returns True on success.
    """
    # Try DB insert when APP_DB_DSN is present
    dsn = os.getenv('APP_DB_DSN')
    if dsn:
        try:
            import asyncpg
            async def _do():
                conn = await asyncpg.connect(dsn)
                try:
                    # ensure table exists (best-effort)
                    await conn.execute('''
                        CREATE TABLE IF NOT EXISTS calibration_runs (
                            id SERIAL PRIMARY KEY,
                            tenant_id TEXT,
                            run_payload JSONB,
                            created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
                        )
                    ''')
                    await conn.execute('''
                        INSERT INTO calibration_runs (tenant_id, run_payload)
                        VALUES ($1, $2::jsonb)
                    ''', run_payload.get('tenant_id'), json.dumps(run_payload))
                finally:
                    await conn.close()
            import asyncio
            try:
                asyncio.get_event_loop().run_until_complete(_do())
                return True
            except Exception:
                # fallback to file
                pass
        except Exception:
            # no asyncpg or DB issues -> fallback to file
            pass
    try:
        p = _ensure_file()
        arr = []
        if os.path.exists(p):
            try:
                with open(p, 'r', encoding='utf-8') as fh:
                    arr = json.load(fh) or []
            except Exception:
                arr = []
        arr.append(run_payload)
        with open(p, 'w', encoding='utf-8') as fh:
            json.dump(arr, fh, indent=2)
        return True
    except Exception:
        return False


__all__ = ['persist_run']
