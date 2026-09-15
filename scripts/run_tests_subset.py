"""Run a subset of tests from batch_order.txt then run the idempotency test.

Usage:
  python scripts/run_tests_subset.py START END

Indexes are 1-based and inclusive. START=1 END=66 will run lines 1..66 from
batch_order.txt and then run tests/test_idempotency.py to see if prior tests
influence its behavior.
"""
import sys
import pathlib
import pytest


def load_order(path):
    # read as bytes then decode with utf-8-sig to tolerate BOM or stray markers
    raw = path.read_bytes()
    for enc in ('utf-8-sig', 'utf-8', 'utf-16', 'utf-16-le', 'utf-16-be'):
        try:
            text = raw.decode(enc)
            break
        except Exception:
            text = None
    if text is None:
        # last resort: latin1
        text = raw.decode('latin1')
    lines = [l.strip() for l in text.splitlines() if l.strip() and not l.startswith('=')]
    # each line is like: path: count
    items = []
    for l in lines:
        if ':' in l:
            p = l.split(':', 1)[0].strip()
            items.append(p)
    return items


def main():
    if len(sys.argv) != 3:
        print('Usage: python scripts/run_tests_subset.py START END')
        return 2
    start = int(sys.argv[1])
    end = int(sys.argv[2])
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    order_f = repo_root / 'batch_order.txt'
    if not order_f.exists():
        print('batch_order.txt not found at', order_f)
        return 2
    items = load_order(order_f)
    if start < 1 or end > len(items) or start > end:
        print('Invalid range', start, end, 'items available', len(items))
        return 2
    subset = items[start-1:end]
    # Ensure idempotency test runs after the subset so we can see its behavior
    idemp = 'tests/test_idempotency.py'
    if idemp in subset:
        args = subset
    else:
        args = subset + [idemp]

    print('Running pytest on', len(subset), 'files then', idemp)
    # Run pytest programmatically
    rc = pytest.main(args + ['-q', '--maxfail=1'])
    sys.exit(rc)


if __name__ == '__main__':
    main()
