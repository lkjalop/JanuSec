#!/usr/bin/env python
"""Update AUTO-DELTA block in architecture_evolution.md

Usage:
  python scripts/update_auto_delta.py --delta-markdown synthetic_delta.md \
      --arch-file docs/architecture_evolution.md

If --delta-markdown omitted, attempts to build table from synthetic_delta.json.

Markers:
  <!--AUTO-DELTA:START-->
  ... managed content ...
  <!--AUTO-DELTA:END-->
"""
from __future__ import annotations
import argparse, json, re
from pathlib import Path

def build_table_from_json(delta_json: Path) -> str:
    data = json.loads(delta_json.read_text(encoding='utf-8'))
    header = "| metric | previous | current | delta | % change |\n|--------|----------|---------|-------|----------|\n"
    rows = []
    for metric, vals in data.items():
        prev = vals.get('previous')
        curr = vals.get('current')
        d = vals.get('delta')
        pct = ''
        try:
            if isinstance(prev,(int,float)) and prev not in (0,None) and metric not in ('false_positive_rate_per_1k',):
                pct = f"{(d/prev)*100:+.2f}%"
        except Exception:
            pct = ''
        rows.append(f"| {metric} | {prev} | {curr} | {d:+.4f} | {pct} |")
    return header + "\n".join(rows) + "\n"

def replace_block(text: str, new_block: str) -> str:
    pattern = r'(<!--AUTO-DELTA:START-->)(.*?)(<!--AUTO-DELTA:END-->)'
    repl = f"\\1\n{new_block}\n\\3"
    return re.sub(pattern, repl, text, flags=re.DOTALL)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--arch-file', default='docs/architecture_evolution.md')
    ap.add_argument('--delta-markdown', help='Pre-rendered markdown table file')
    ap.add_argument('--delta-json', default='synthetic_delta.json', help='JSON deltas if markdown not supplied')
    args = ap.parse_args()
    arch_path = Path(args.arch_file)
    if not arch_path.exists():
        raise SystemExit(f"Architecture file not found: {arch_path}")
    if args.delta_markdown:
        table = Path(args.delta_markdown).read_text(encoding='utf-8')
    else:
        dj = Path(args.delta_json)
        if not dj.exists():
            raise SystemExit('No delta markdown or json found')
        table = build_table_from_json(dj)
    content = arch_path.read_text(encoding='utf-8')
    updated = replace_block(content, table.strip())
    arch_path.write_text(updated, encoding='utf-8')
    print(f"Updated AUTO-DELTA block in {arch_path}")

if __name__ == '__main__':
    main()
