#!/usr/bin/env python3
"""Migrate IAM connector secrets into the configured Vault backend.

This script scans artifacts/config/iam_connectors.json (or the override set via
IAM_CONNECTORS_PATH), detects plaintext secrets, pushes them into the selected
vault backend, and rewrites each connector entry to the `_vault_key` pointer
that the API/UI expect. Run with --dry-run to preview changes.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict

from src.api import iam_connector_endpoints as iam_cfg
from src.secrets.vault import set_secret as vault_set_secret


def _iter_secret_fields(defn: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {}
    for field in defn.get('fields', []):
        name = field.get('name')
        if not name:
            continue
        if field.get('secret') or iam_cfg._secret_field(name):  # type: ignore[attr-defined]
            result[name] = field
    return result


def migrate(dry_run: bool = False, verbose: bool = False) -> int:
    cfg = iam_cfg._load_config()  # type: ignore[attr-defined]
    cfg_path = iam_cfg._config_path()  # type: ignore[attr-defined]
    original_text = None
    if cfg_path.exists():
        try:
            original_text = cfg_path.read_text(encoding='utf-8')
        except Exception:
            original_text = None
    tenants = cfg.get('tenants') or {}
    changed = False
    total = 0
    for tenant, connectors in tenants.items():
        if not isinstance(connectors, dict):
            continue
        for connector_id, stored in connectors.items():
            defn = iam_cfg.CONNECTOR_MAP.get(connector_id)
            if not defn or not isinstance(stored, dict):
                continue
            secret_fields = _iter_secret_fields(defn)
            for field_name in secret_fields:
                value = stored.get(field_name)
                if isinstance(value, dict) and value.get('_vault_key'):
                    continue
                if not value or not isinstance(value, str):
                    continue
                key = iam_cfg._vault_secret_key(tenant, connector_id, field_name)  # type: ignore[attr-defined]
                total += 1
                if dry_run:
                    print(f"[dry-run] would migrate {tenant}/{connector_id}.{field_name} -> {key}")
                    continue
                ok = vault_set_secret(key, value)
                if not ok:
                    print(f"[warn] failed to persist {key}; leaving plaintext value in place", file=sys.stderr)
                    continue
                stored[field_name] = {'_vault_key': key}
                changed = True
                if verbose:
                    print(f"[migrated] {tenant}/{connector_id}.{field_name} -> {key}")
    if changed and not dry_run:
        backup = Path(str(cfg_path) + '.bak')
        if original_text is not None:
            try:
                backup.write_text(original_text, encoding='utf-8')
            except Exception:
                print(f"[warn] failed to write backup to {backup}", file=sys.stderr)
        iam_cfg._save_config(cfg)  # type: ignore[attr-defined]
        print(f"[done] Updated {cfg_path} (backup at {backup}) with migrated vault keys.")
    elif not changed and not dry_run:
        print("[info] No plaintext secrets detected; nothing to migrate.")
    return total


def main() -> int:
    parser = argparse.ArgumentParser(description='Migrate IAM connector secrets into the configured vault backend.')
    parser.add_argument('--dry-run', action='store_true', help='Report secrets that would be migrated without writing.')
    parser.add_argument('--verbose', action='store_true', help='Print each migrated secret path.')
    args = parser.parse_args()
    try:
        total = migrate(dry_run=args.dry_run, verbose=args.verbose)
    except Exception as exc:
        print(f"[error] migration failed: {exc}", file=sys.stderr)
        return 1
    if args.dry_run:
        print(f"[dry-run] identified {total} plaintext secret(s) ready for migration.")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
