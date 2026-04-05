from __future__ import annotations

import argparse
import shutil
import os
from pathlib import Path


import json
import time


def _load_index(path: Path):
    idx = {}
    try:
        if path.exists():
            idx = json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        idx = {}
    return idx


def _write_index(path: Path, idx):
    try:
        path.write_text(json.dumps(idx, indent=2), encoding='utf-8')
    except Exception:
        pass


def promote(src: str, name: str | None = None, alias: str | None = None) -> int:
    src_p = Path(src)
    if not src_p.exists():
        print(f"Source model not found: {src}")
        return 2
    registry = Path('models/registry')
    registry.mkdir(parents=True, exist_ok=True)
    # supply a timestamped default name when not provided
    if not name:
        name = f"model-{int(time.time())}"
    dest = registry / f"{name}.json"
    shutil.copy2(src_p, dest)
    print(f"Copied model to {dest}")

    # update registry index
    idx_path = registry / 'index.json'
    idx = _load_index(idx_path)
    idx.setdefault('models', []).append({'name': name, 'path': str(dest), 'ts': int(time.time())})
    # maintain alias mapping
    aliases = idx.get('aliases', {})
    if alias:
        aliases[alias] = name
        idx['aliases'] = aliases
    _write_index(idx_path, idx)

    if alias:
        alias_path = Path('models') / alias
        alias_json = Path('models') / f"{alias}.json"
        # remove existing
        try:
            if alias_path.exists() or alias_path.is_symlink():
                if alias_path.is_dir():
                    # unexpected, skip
                    pass
                else:
                    alias_path.unlink()
        except Exception:
            pass
        # try to create symlink (best-effort)
        try:
            # create relative symlink
            rel = os.path.relpath(dest, alias_path.parent)
            alias_path.symlink_to(rel)
            print(f"Created symlink {alias_path} -> {rel}")
        except Exception:
            # fallback: copy to models/<alias>.json
            try:
                shutil.copy2(dest, alias_json)
                print(f"Symlink failed, copied to {alias_json} as fallback")
            except Exception as e:
                print(f"Failed to set alias: {e}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description='Promote a model into the registry')
    p.add_argument('--src', required=True, help='Source model JSON path')
    p.add_argument('--name', required=True, help='Registry name (e.g. sigmoid-20251004-1200)')
    p.add_argument('--alias', required=False, help='Optional alias name (e.g. current)')
    args = p.parse_args(argv)
    return promote(args.src, args.name, args.alias)


if __name__ == '__main__':
    raise SystemExit(main())
