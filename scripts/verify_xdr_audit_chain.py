"""Verify XDR webhook audit hash chains per integrator.

Usage (example):
  python -m scripts.verify_xdr_audit_chain --path artifacts/xdr_audit

Exit code 0 if all chains valid, 1 if any corruption detected.
"""
from __future__ import annotations
import argparse, json, os, sys, hashlib
from typing import List, Tuple

def verify_file(path: str) -> Tuple[bool, List[str]]:
    errors: List[str] = []
    prev = None
    line_no = 0
    try:
        with open(path,'r',encoding='utf-8') as f:
            for line in f:
                line_no += 1
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    errors.append(f"{path}:{line_no} invalid json")
                    continue
                claimed_prev = obj.get('prev_hash')
                claimed_hash = obj.get('hash')
                body = {k:v for k,v in obj.items() if k not in ('hash')}
                canon = json.dumps({k:v for k,v in body.items() if k!='hash'}, sort_keys=True, separators=(',',':')).encode()
                calc = hashlib.sha256(canon).hexdigest()
                if claimed_hash != calc:
                    errors.append(f"{path}:{line_no} hash mismatch")
                if claimed_prev != prev:
                    errors.append(f"{path}:{line_no} prev_hash mismatch (expected {prev})")
                prev = claimed_hash
    except FileNotFoundError:
        errors.append(f"file not found: {path}")
    return (len(errors)==0, errors)

def main():
    ap = argparse.ArgumentParser(description='Verify XDR audit chains')
    ap.add_argument('--path', default='artifacts/xdr_audit', help='Audit directory path')
    args = ap.parse_args()
    root = args.path
    if not os.path.isdir(root):
        print(f"Directory not found: {root}", file=sys.stderr)
        sys.exit(1)
    any_errors = False
    for fn in os.listdir(root):
        if not fn.endswith('.jsonl'): continue
        full = os.path.join(root, fn)
        ok, errs = verify_file(full)
        if ok:
            print(f"OK  {fn}")
        else:
            any_errors = True
            print(f"FAIL {fn}")
            for e in errs:
                print('  -', e)
    sys.exit(0 if not any_errors else 1)

if __name__ == '__main__':
    main()
