"""Small utility to generate FACTOR_TO_MITRE mapping from a local CSV/JSON source.

Usage (dev):
  python -m src.tools.generate_mitre_map path/to/mappings.csv > src/core/mappings/factor_to_mitre_generated.py

CSV expected columns: factor,mitre_ids (comma-separated)
JSON expected format: [{"factor":"...","mitre_ids":["T...", ...]}, ...]
"""
from __future__ import annotations
import sys, json, csv
from pathlib import Path
from typing import List


def load_csv(path: Path) -> List[dict]:
    out = []
    with path.open('r', encoding='utf-8') as f:
        r = csv.DictReader(f)
        for row in r:
            ids = [s.strip() for s in (row.get('mitre_ids') or '').split(',') if s.strip()]
            out.append({'factor': row.get('factor',''), 'mitre_ids': ids})
    return out


def load_json(path: Path) -> List[dict]:
    data = json.loads(path.read_text(encoding='utf-8'))
    if isinstance(data, list):
        return data
    return []


def main(argv):
    if len(argv) < 2:
        print('Usage: generate_mitre_map.py <input.csv|json>')
        return 2
    p = Path(argv[1])
    if not p.exists():
        print('File not found', p)
        return 2
    if p.suffix.lower() in ('.csv',):
        items = load_csv(p)
    else:
        items = load_json(p)
    mapping = {it['factor']: it['mitre_ids'] for it in items}
    print('# Generated mapping')
    print('FACTOR_TO_MITRE = {')
    for k,v in mapping.items():
        print(f"    {json.dumps(k)}: {json.dumps(v)},")
    print('}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
