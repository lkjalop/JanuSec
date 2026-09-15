# Approval Store Migration Guide

This guide explains how to migrate the prototype JSONL approval store into
the SQLite-backed approvals DB used in production/larger demos.

Files:
- `data/approvals/approvals.jsonl` — existing append-only event log (prototype)
- `data/approvals.db` — default SQLite DB path used when `USE_APPROVAL_DB=1`

Migration script:

`python scripts/migrate_approvals_to_db.py --file data/approvals/approvals.jsonl --apply`

Options:
- `--apply`: actually write into the DB (default is dry-run)
- `--force`: re-import tokens even if already seen (idempotent mode skips duplicates by default)

Notes:
- The migration writes both the current approvals table and an `approval_events`
  timeline table capturing request/approve/revoke events for audit and multi-approver support.
- After migration, enable DB mode by setting `USE_APPROVAL_DB=1` and optionally
  set `APPROVAL_DB_PATH` to point to the DB file.
