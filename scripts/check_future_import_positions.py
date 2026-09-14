import sys
import os
from pathlib import Path

pattern = 'from __future__ import annotations'

def is_top_position(fp: Path) -> bool:
    # Return True if the first non-blank, non-comment line is the pattern
    try:
        with fp.open('r', encoding='utf-8') as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith('#'):
                    continue
                return s == pattern
    except Exception:
        return True
    return False


def main():
    repo = Path('.').resolve()
    matches = []
    candidates = []
    skip_tokens = ('.venv', 'venv', '\\venv', '/venv', 'env', '.git')
    for root, dirs, files in os.walk(repo, topdown=True):
        lowroot = root.lower()
        if any(tok in lowroot for tok in skip_tokens):
            # skip walking into this tree
            dirs[:] = []
            continue
        # prune dirs in-place that are venv/git
        dirs[:] = [d for d in dirs if not any(tok in d.lower() for tok in skip_tokens)]
        for fn in files:
            if fn.endswith('.py'):
                candidates.append(Path(root) / fn)
    for p in candidates:
        try:
            text = p.read_text(encoding='utf-8')
        except Exception:
            continue
        if pattern in text:
            top_ok = is_top_position(p)
            matches.append({'path': str(p), 'top_ok': top_ok})

    bad = [m for m in matches if not m['top_ok']]
    print(f'total_with_pattern={len(matches)} bad_count={len(bad)}')
    if bad:
        print('\nFiles where future import is NOT top-of-file:')
        for b in bad:
            print(b['path'])
    else:
        print('All occurrences are top-of-file (or files unreadable).')


if __name__ == '__main__':
    main()
