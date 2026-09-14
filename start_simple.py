#!/usr/bin/env python3
"""
Simple JanuSec Server Startup Script
Starts just the FastAPI server with CSV processing capabilities
"""

import os
import sys
import uvicorn
from pathlib import Path
import argparse

try:
    from dotenv import load_dotenv  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    load_dotenv = None

# Add repo root to Python path (src/ must NOT be at top-level; use src.api.* imports)
current_dir = Path(__file__).parent
src_dir = current_dir / "src"
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))

# Set required environment variables
# Load environment variables from .env (if available) before applying defaults.
if load_dotenv:
    env_path = current_dir / ".env"
    # only log when the file exists and we successfully loaded it
    if env_path.exists():
        if load_dotenv(env_path, override=False):
            print(f"[env] Loaded settings from {env_path}")
else:
    print("[env] python-dotenv not installed; skipping .env load")

os.environ.setdefault("PYTHONPATH", str(current_dir))
os.environ.setdefault("EVENT_QUEUE_MAX", "2000")
os.environ.setdefault("ACCESS_LOG_SAMPLE_RATE", "0.5")
os.environ.setdefault("API_KEYS_JSON", '[{"key":"devkey123","scopes":["*"]}]')
os.environ.setdefault("ENABLE_CSV_UPLOAD", "true")
os.environ.setdefault("ECLIPSE_XDR_SHARED_SECRET", "dev_secret")
os.environ.setdefault("DEFAULT_FRONTEND", "console")
os.environ.setdefault("APP_ENV", "dev")
os.environ.setdefault("ENV", "dev")

def main():
    """Start the server with minimal dependencies"""

    parser = argparse.ArgumentParser(description="Start the JanuSec demo server")
    parser.add_argument("--no-reload", action="store_true", help="Disable uvicorn auto-reload (stability / troubleshooting)")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080)")
    parser.add_argument("--log-level", default=os.getenv("LOG_LEVEL", "info"), help="Log level (default: info)")
    args, _unknown = parser.parse_known_args()

    print("=" * 50)
    print("Starting JanuSec Platform")
    print("=" * 50)
    print()
    print(f"Server: http://{args.host}:{args.port}")
    print(f"Console: http://{args.host}:{args.port}/console")
    print(f"CSV Upload: http://{args.host}:{args.port}/api/v1/csv/upload-page")
    print(f"API Docs: http://{args.host}:{args.port}/docs")
    print()
    print("Press Ctrl+C to stop")
    print("=" * 50)

    try:
        # Import side-effect initializes components
        from src.api.server import app  # noqa: F401

        # Precedence: --no-reload flag overrides env var if provided
        if args.no_reload:
            reload_flag = False
            reload_source = "--no-reload flag"
        else:
            reload_flag = os.getenv("UVICORN_RELOAD", "1").lower() in {"1", "true", "yes"}
            reload_source = "UVICORN_RELOAD env" if "UVICORN_RELOAD" in os.environ else "default (enabled)"

        if os.name == "nt" and reload_flag:
            # Windows file watcher + large codebase can be unstable; give a hint
            print("[hint] If the server exits immediately, retry with --no-reload to disable the watcher on Windows.")

        print(f"[startup] reload={reload_flag} (source: {reload_source})  log_level={args.log_level}")
        uvicorn.run(
            "src.api.server:app",
            host=args.host,
            port=args.port,
            reload=reload_flag,
            reload_dirs=[str(current_dir)] if reload_flag else None,
            log_level=args.log_level,
        )
    except KeyboardInterrupt:
        print("\n👋 Server stopped")
    except Exception as e:
        print(f"❌ Error starting server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
