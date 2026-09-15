"""Drain the writeback DLQ and attempt to re-post payloads.

This script reads up to N items from the simple file-based DLQ and
retries posting them using their recorded metadata. It is best-effort
and should be used for operator retries or as a CI/maintenance task.
"""
import json
import os
import sys
from typing import Any

from src.core.durable_dlq import drain
from src.core.idempotency import IdempotencyStore, run_idempotent
import os
import hashlib

# idempotency DB path can be controlled via IDEMPOTENCY_DB env var
idemp = IdempotencyStore()


def attempt_repost(item: Any) -> bool:
    # item expected to contain base_url, api_key, tenant_id, and events/findings
    try:
        base = item.get('base_url') or item.get('base')
        api = item.get('api_key')
        tid = item.get('tenant_id') or item.get('tenant')
        payload = json.dumps(item.get('events') or item.get('findings') or {}).encode('utf-8')
        if not base or not api or not tid:
            print('missing metadata for repost; skipping')
            return False
        # Build an idempotency key from base + tenant + payload hash
        raw_key = '|'.join([base, tid, hashlib.sha256(payload).hexdigest()])

        def _do_repost():
            import urllib.request
            req = urllib.request.Request(
                f"{base.rstrip('/')}/api/v1/ingest/repair",
                data=payload,
                method='POST',
                headers={'Content-Type': 'application/json', 'x-api-key': api, 'x-tenant-id': tid},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.read()

        try:
            run_idempotent(idemp, raw_key, _do_repost)
            return True
        except RuntimeError as e:
            print('idempotency in progress, skipping for now:', e)
            return False
        except Exception as e:
            print('repost failed:', e)
            return False
    except Exception as e:
        print('repost failed:', e)
        return False


def main():
    items = drain(limit=100)
    print('drain returned', len(items), 'items')
    success = 0
    for it in items:
        if attempt_repost(it):
            success += 1
    print(f'Reposted {success}/{len(items)} items')


if __name__ == '__main__':
    main()
