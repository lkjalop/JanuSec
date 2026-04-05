from typing import Any

def ensure_iam_cursors_table() -> None:
    try:
        from src.db.database import get_db, Database  # type: ignore
        db: Database = get_db()
        db.execute("CREATE TABLE IF NOT EXISTS iam_cursors(provider TEXT PRIMARY KEY, since TEXT)")  # type: ignore
        # Optional index (redundant for PRIMARY KEY but kept for clarity in some backends)
        db.execute("CREATE INDEX IF NOT EXISTS idx_iam_cursors_provider ON iam_cursors(provider)")  # type: ignore
    except Exception:
        # Best-effort migration; swallow errors in environments without DB
        pass
