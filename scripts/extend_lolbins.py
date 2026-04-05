"""Extend or validate data/lolbins.yaml with additional entries.

Usage:
  python scripts/extend_lolbins.py --source extra_lolbins.yaml
  python scripts/extend_lolbins.py --validate

This helper merges entries and deduplicates by key.
"""
from __future__ import annotations
import argparse
import yaml
from pathlib import Path

LOLBINS_PATH = Path("data/lolbins.yaml")


def load_yaml(p: Path) -> dict:
    if not p.exists():
        return {}
    with p.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def write_yaml(p: Path, data: dict) -> None:
    with p.open("w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", help="YAML file with extra entries to merge", default=None)
    parser.add_argument("--validate", help="Validate current lolbins file", action="store_true")
    args = parser.parse_args()

    base = load_yaml(LOLBINS_PATH)

    if args.validate:
        print(f"Loaded {len(base)} lolbin entries from {LOLBINS_PATH}")
        # quick sanity checks
        missing = [k for k,v in base.items() if not isinstance(v, dict) or 'aliases' not in v]
        if missing:
            print("Warning: some entries missing aliases or malformed:", missing[:10])
        else:
            print("Sanity checks passed")
        raise SystemExit(0)

    if args.source:
        srcp = Path(args.source)
        if not srcp.exists():
            print("Source file not found:", srcp)
            raise SystemExit(2)
        extras = load_yaml(srcp)
        merged = dict(base)
        merged.update(extras)
        write_yaml(LOLBINS_PATH, merged)
        print(f"Merged {len(extras)} entries; total now {len(merged)}")