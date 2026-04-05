"""Run an ordered slice from batch_order.txt and optionally append an extra test file.

Usage:
  python scripts/run_tests_ordered.py START END [EXTRA]

This runs pytest in-process with the selected files in their listed order.
"""
import sys
import pathlib
import pytest

if len(sys.argv) < 3:
    print('Usage: python scripts/run_tests_ordered.py START END [EXTRA]')
    sys.exit(2)

start = int(sys.argv[1])
end = int(sys.argv[2])
extra = sys.argv[3] if len(sys.argv) > 3 else None
repo_root = pathlib.Path(__file__).resolve().parents[1]
order_f = repo_root / 'batch_order.txt'
if not order_f.exists():
    print('batch_order.txt not found at', order_f)
    sys.exit(2)
raw = order_f.read_text(encoding='utf-8-sig')
lines = [l.strip() for l in raw.splitlines() if l.strip() and not l.startswith('=')]
items = []
for l in lines:
    if ':' in l:
        p = l.split(':', 1)[0].strip()
        items.append(p)
if start < 1 or end > len(items) or start > end:
    print('Invalid range', start, end, 'items available', len(items))
    sys.exit(2)
subset = items[start-1:end]
if extra:
    subset.append(extra)
print('Running pytest on', len(subset), 'files:')
for s in subset:
    print(' -', s)
rc = pytest.main(subset + ['-q', '--maxfail=1', '-vv'])
sys.exit(rc)
