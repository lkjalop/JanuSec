"""One-shot enrichment seeder: runs the seed job once and exits.

Usage:
  python scripts/seed_enrichment.py
Set env ENABLE_ENRICHMENT_WORKER=1 and KEV/EPSS keys if available.
"""
import asyncio
import os
import sys
from pathlib import Path

if __name__ == '__main__':
    # ensure project root
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))
    os.environ.setdefault('FAST_TEST_MODE', '1')
    os.environ.setdefault('ENABLE_ENRICHMENT_WORKER', '1')
    try:
        from src.enrichment.worker import _seed_from_sessions
    except Exception:
        from enrichment.worker import _seed_from_sessions

    asyncio.run(_seed_from_sessions(limit=200))
    print('seed complete')
