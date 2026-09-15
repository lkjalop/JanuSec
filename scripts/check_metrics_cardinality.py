from __future__ import annotations
import re, sys, pathlib

"""Simple heuristic metrics cardinality budget check.

Scans source for prometheus Counter/Gauge/Histogram instantiations and counts
unique metric names. Fails if exceeding threshold (env or arg; default 150).

Usage:
  python scripts/check_metrics_cardinality.py [max_metrics]
Returns non-zero exit if threshold exceeded.
"""

METRIC_RE = re.compile(r"\b(Counter|Gauge|Histogram)\(\s*['\"]([a-zA-Z0-9_:]+)['\"]) ")

def main():
    root = pathlib.Path(__file__).resolve().parents[1]
    max_metrics = int(sys.argv[1]) if len(sys.argv) > 1 else int(
        (pathlib.os.getenv('METRICS_MAX_TOTAL') or 150)
    )
    names = set()
    for p in root.rglob('*.py'):
        try:
            txt = p.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            continue
        for m in METRIC_RE.finditer(txt):
            names.add(m.group(2))
    print(f"Metrics discovered: {len(names)} (threshold {max_metrics})")
    if len(names) > max_metrics:
        print("ERROR: Metric count exceeds budget.", file=sys.stderr)
        for n in sorted(names):
            print(n)
        sys.exit(1)
    print("OK: within metrics budget.")

if __name__ == '__main__':
    main()