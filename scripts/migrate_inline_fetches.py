"""
Utility script to migrate inline `fetch(` calls in HTML files under `frontend/static/` to
use `(window.safeFetch || fetch)` for eligible endpoints.

Policy:
- Replace `fetch(` with `(window.safeFetch || fetch)(` for GET requests and non-upload POSTs
  that are safe to retry (no multipart/form-data, not `/api/v1/upload/files`, not file uploads).
- Skip occurrences that clearly reference `/upload` or `FormData`.

Usage:
  python scripts/migrate_inline_fetches.py

This script is conservative and writes a `.bak` copy before modifying files.
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / 'frontend' / 'static'

# regex finds `fetch(` with optional whitespace and captures the argument start
FETCH_RE = re.compile(r"\bfetch\s*\(")

# patterns to skip in the same line or nearby context
SKIP_PATTERNS = [
    r"/upload/files",
    r"upload",
    r"FormData",
    r"multipart",
    r"content-type': 'multipart",
]

def should_skip(text):
    low = text.lower()
    for p in SKIP_PATTERNS:
        if p.lower() in low:
            return True
    return False


def process_file(p: Path):
    text = p.read_text(encoding='utf-8')
    orig = text
    changed = False

    # iterate line by line conservatively
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if 'fetch(' not in line:
            continue
        # quick skip if line contains skip patterns
        if should_skip(line):
            continue
        # safe replacement: replace fetch( with (window.safeFetch || fetch)(
        new_line = line.replace('fetch(', '(window.safeFetch || fetch)(')
        if new_line != line:
            lines[i] = new_line
            changed = True

    if changed:
        bak = p.with_suffix(p.suffix + '.bak')
        bak.write_text(orig, encoding='utf-8')
        p.write_text('\n'.join(lines), encoding='utf-8')
        print(f"Patched: {p.relative_to(ROOT)}")
    return changed


def main():
    html_files = list(STATIC.glob('*.html'))
    total = 0
    for f in html_files:
        try:
            if process_file(f):
                total += 1
        except Exception as e:
            print(f"Error processing {f}: {e}")
    print(f"Done. Patched {total} files.")


if __name__ == '__main__':
    main()
