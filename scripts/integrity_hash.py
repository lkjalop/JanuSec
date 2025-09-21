"""Compute a deterministic integrity hash of repository (excluding .git directory).

Usage:
  python scripts/integrity_hash.py
"""
from __future__ import annotations
import hashlib, os, sys

EXCLUDE_DIRS = {'.git','__pycache__'}

def iter_files(root: str):
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for f in sorted(files):
            path = os.path.join(base, f)
            yield path

def file_hash(path: str) -> str:
    h = hashlib.sha256()
    with open(path,'rb') as fp:
        while True:
            chunk = fp.read(8192)
            if not chunk: break
            h.update(chunk)
    return h.hexdigest()

def main():
    pairs = []
    for p in iter_files('.'):
        pairs.append((p, file_hash(p)))
    pairs.sort(key=lambda x: x[0])
    roll = hashlib.sha256()
    for p,h in pairs:
        roll.update(f"{p}:{h}\n".encode())
    print(roll.hexdigest())

if __name__ == '__main__':
    main()
