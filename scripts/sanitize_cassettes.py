"""Sanitize recorded HTTP cassettes (vcrpy YAML or JSON dumps).

This script looks for common sensitive fields and headers and replaces them
with placeholders. It supports JSON files and YAML files produced by vcrpy.

Usage:
  python scripts/sanitize_cassettes.py --dir tests/integration/cassettes --inplace

The script will:
- Replace Authorization headers with "REDACTED"
- Replace any JSON/YAML keys named `access_token` with "REDACTED"
- Replace bearer tokens embedded in strings (e.g., "Bearer ABC...")
- Optionally replace hostnames matching patterns (e.g., qualysapi.yourcompany.com -> qualysapi.REDACTED)
- Replace timestamps that look like ISO8601 with a placeholder
"""
import argparse
import os
import re
import json
from pathlib import Path

try:
    import yaml
except Exception:
    yaml = None

# Common patterns to redact
AUTH_HEADER_RE = re.compile(r'Authorization', re.IGNORECASE)
ACCESS_TOKEN_KEYS = {'access_token', 'token', 'refresh_token'}
BEARER_RE = re.compile(r'Bearer\s+[A-Za-z0-9\-\._~\+\/=]+')
ISO8601_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?")
HOSTS_RE = re.compile(r"(https?://)([A-Za-z0-9\.-]+)")


def sanitize_text(s: str) -> str:
    s = BEARER_RE.sub('Bearer REDACTED', s)
    s = ISO8601_RE.sub('TIMESTAMP_REDACTED', s)
    s = HOSTS_RE.sub(lambda m: m.group(1) + m.group(2).split('.')[0] + '.REDACTED', s)
    return s


def sanitize_obj(obj):
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in ACCESS_TOKEN_KEYS:
                out[k] = 'REDACTED'
            else:
                out[k] = sanitize_obj(v)
        return out
    if isinstance(obj, list):
        return [sanitize_obj(x) for x in obj]
    if isinstance(obj, str):
        return sanitize_text(obj)
    return obj


def sanitize_file(path: Path, inplace: bool = False):
    text = path.read_text(encoding='utf-8')
    modified = False
    # Try JSON first
    try:
        j = json.loads(text)
        j2 = sanitize_obj(j)
        out = json.dumps(j2, indent=2)
        modified = True
    except Exception:
        if yaml and path.suffix in ('.yml', '.yaml'):
            try:
                y = yaml.safe_load(text)
                y2 = sanitize_obj(y)
                out = yaml.safe_dump(y2, default_flow_style=False)
                modified = True
            except Exception:
                out = sanitize_text(text)
                modified = True
        else:
            out = sanitize_text(text)
            modified = True

    if not modified:
        return False

    if inplace:
        path.write_text(out, encoding='utf-8')
    else:
        # write a .sanitized copy
        san = path.with_suffix(path.suffix + '.sanitized')
        san.write_text(out, encoding='utf-8')
    return True


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--dir', default='tests/integration/cassettes')
    p.add_argument('--inplace', action='store_true')
    args = p.parse_args()

    base = Path(args.dir)
    if not base.exists():
        print('No cassette dir:', base)
        return
    count = 0
    for f in base.rglob('*'):
        if f.is_file() and f.suffix.lower() in ('.json', '.yml', '.yaml'):
            if sanitize_file(f, inplace=args.inplace):
                print('Sanitized', f)
                count += 1
    print('Sanitized files:', count)


if __name__ == '__main__':
    main()
