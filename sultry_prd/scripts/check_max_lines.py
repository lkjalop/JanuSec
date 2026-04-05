#!/usr/bin/env python3
"""Simple file length checker for Sultry PRD CI.
Checks .py, .html, .json files and warns if > 400 lines.
Exit non-zero if any file exceeds threshold.
"""
import os
import sys

THRESHOLD = 400

def check_file(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception:
        return False, 0
    return len(lines) <= THRESHOLD, len(lines)

def main(root='.'):
    failures = []
    for dirpath, _, filenames in os.walk(root):
        # skip virtualenvs and git
        if '.git' in dirpath or 'venv' in dirpath or '.venv' in dirpath:
            continue
        for fn in filenames:
            if fn.endswith(('.py', '.html', '.json')):
                path = os.path.join(dirpath, fn)
                ok, count = check_file(path)
                if not ok:
                    failures.append((path, count))
                    print(f'FILE_TOO_LONG: {path} ({count} lines)')
    if failures:
        print(f'Found {len(failures)} files exceeding {THRESHOLD} lines.')
        return 2
    print('All files within line threshold.')
    return 0

if __name__ == '__main__':
    sys.exit(main(os.path.dirname(os.path.dirname(__file__))))
