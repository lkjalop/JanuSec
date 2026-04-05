"""Verify integrity hash chain for alert JSONL log.

Each line must contain fields: id, prev_hash (may be null/empty on first), hash.
If a mismatch is found, the script prints the failing line number and exits non-zero.

Usage:
  python scripts/verify_alert_chain.py --path artifacts/alerts/alerts.jsonl
"""
from __future__ import annotations
import argparse, json, hashlib, sys, os

def compute(prev_hash: str, payload: dict) -> str:
    # Exclude existing hash fields to avoid recursion
    body = {k: v for k, v in payload.items() if k not in {"hash"}}
    serialized = json.dumps(body, sort_keys=True, separators=(",",":"))
    return hashlib.sha256((prev_hash or "") + serialized).hexdigest()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", default=os.getenv("ALERT_CHAIN_PATH", "artifacts/alerts/alerts.jsonl"))
    args = ap.parse_args()

    if not os.path.exists(args.path):
        print(f"File not found: {args.path}")
        sys.exit(1)

    prev = None
    ok = True
    with open(args.path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception as e:
                print(f"Line {i}: invalid json: {e}")
                ok = False
                break
            expected = compute(prev, obj)
            actual = obj.get("hash")
            if expected != actual:
                print(f"Line {i}: hash mismatch expected={expected} actual={actual}")
                ok = False
                break
            prev = actual
    if ok:
        print("Hash chain VALID ✅")
    else:
        print("Hash chain INVALID ❌")
        sys.exit(2)

if __name__ == "__main__":
    main()
