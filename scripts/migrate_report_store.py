"""Lightweight migration helper: move in-memory REPORT_STORE dicts into chosen storage backend.

Usage:
  python scripts/migrate_report_store.py

Set env vars to control target backend:
  STORAGE_BACKEND=postgres|redis|file|memory
  DATABASE_URL, REDIS_URL as needed
"""
from __future__ import annotations
import sys
import os
import importlib
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def collect_inmemory_sources():
    sources = []
    # Try common modules first
    cand_modules = [
        'src.api.deep_analyze_endpoints',
        'src.api.csv_endpoints',
        'src.api.app',
    ]
    for name in cand_modules:
        try:
            mod = importlib.import_module(name)
            rs = getattr(mod, 'REPORT_STORE', None)
            if isinstance(rs, dict) and rs:
                sources.append((name, rs))
        except Exception:
            continue
    # scan sys.modules for any REPORT_STORE dicts
    for nm, mod in list(sys.modules.items()):
        try:
            rs = getattr(mod, 'REPORT_STORE', None)
            if isinstance(rs, dict) and rs:
                if (nm, rs) not in sources:
                    sources.append((nm, rs))
        except Exception:
            continue
    return sources


def main(dry_run: bool = False, force: bool = False):
    logger.info('Starting report store migration dry_run=%s force=%s', dry_run, force)
    try:
        from src.core.storage.report_store import migrate_from_inmemory, report_store
    except Exception as e:
        logger.exception('Unable to import report_store: %s', e)
        return
    sources = collect_inmemory_sources()
    total = 0
    for name, src in sources:
        try:
            logger.info('Found module %s (%d items) for potential migration', name, len(src))
            to_migrate = []
            for k in list(src.keys()):
                try:
                    exists = report_store.get(k)
                except Exception:
                    exists = None
                if exists and not force:
                    logger.info('Skipping existing key %s (use --force to override)', k)
                    continue
                to_migrate.append(k)
            if not to_migrate:
                logger.info('No items to migrate from %s', name)
                continue
            if dry_run:
                logger.info('Dry-run: would migrate %d items from %s', len(to_migrate), name)
                continue
            # perform migration for selected keys
            migrated = 0
            for k in to_migrate:
                try:
                    migrate_from_inmemory({k: src.get(k)})
                    migrated += 1
                except Exception:
                    logger.exception('Failed migrating key %s from %s', k, name)
            total += migrated
            logger.info('Migrated %d items from %s', migrated, name)
        except Exception:
            logger.exception('Migration failed for %s', name)
    logger.info('Migration complete. Total migrated: %d', total)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--dry-run', action='store_true', help='Do not persist changes; only report')
    parser.add_argument('--force', action='store_true', help='Overwrite existing keys in target')
    args = parser.parse_args()
    main(dry_run=args.dry_run, force=args.force)
