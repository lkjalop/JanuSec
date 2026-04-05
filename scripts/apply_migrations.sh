#!/usr/bin/env bash
# Apply SQL migrations (intended for CI / startup)
python - <<'PY'
from migrations.alembic_env import __name__
import migrations.alembic_env as m
if __name__ == '__main__':
    pass
PY
python migrations/alembic_env.py
