#!/usr/bin/env python3
"""Wrapper to start the ASGI app with controlled env and sys.path so child process has correct imports.

This script sets minimal environment variables required by the demo server and then imports
the FastAPI `app` object from `src.api.server` and runs uvicorn with that app.
"""
import os
import sys
import pathlib
import importlib


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
# Ensure repo root is on sys.path so `import src.*` works
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
# Also add the `src` folder so imports that expect top-level packages (e.g. `security.auth`)
# resolve when modules are under `src/`.
SRC_DIR = REPO_ROOT / 'src'
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# Minimal env defaults used by start_simple.py
os.environ.setdefault('EVENT_QUEUE_MAX', '2000')
os.environ.setdefault('API_KEYS_JSON', '[{"key":"devkey123","scopes":["*"]}]')
os.environ.setdefault('ENABLE_CSV_UPLOAD', 'true')
os.environ.setdefault('DEFAULT_FRONTEND', 'console')


def main():
    try:
        mod = importlib.import_module('src.api.server')
    except Exception as e:
        print('Failed to import src.api.server:', e, file=sys.stderr)
        raise

    app = getattr(mod, 'app', None)
    if app is None:
        print('src.api.server does not expose `app`', file=sys.stderr)
        raise SystemExit(2)

    try:
        import uvicorn
    except Exception as e:
        print('uvicorn not installed:', e, file=sys.stderr)
        raise

    # Run uvicorn using the app object so we avoid import-string quirks
    port = int(os.environ.get('PORT', os.environ.get('UVICORN_PORT', '8080')))
    uvicorn.run(app, host='0.0.0.0', port=port, log_level='info')


if __name__ == '__main__':
    main()
