import os
import json
import argparse
from pathlib import Path
from src.core import approval_repo


def load_jsonl(path):
    out = []
    if not os.path.exists(path):
        return out
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    return out


def migrate(jsonl_path, dry_run=True, force=False):
    events = load_jsonl(jsonl_path)
    print(f'Found {len(events)} events in {jsonl_path}')
    if dry_run:
        return events
    # Ensure DB exists
    approval_repo.init_db()
    seen_tokens = set()
    for ev in events:
        token = ev.get('token')
        event = ev.get('event')
        if not token or not event:
            continue
        # idempotent: skip tokens already imported unless force
        if not force and token in seen_tokens:
            continue
        seen_tokens.add(token)
        if event == 'request':
            req = ev.get('request') or {}
            approval_repo.save_request(token, req, ev.get('expires_at'))
            approval_repo.append_event(token, 'request', {'request': req, 'expires_at': ev.get('expires_at')})
        elif event == 'approve':
            approval_repo.save_approve(token, ev.get('approver'), ev.get('note'))
            approval_repo.append_event(token, 'approve', {'approver': ev.get('approver'), 'note': ev.get('note')})
        elif event == 'revoke':
            approval_repo.save_revoke(token, ev.get('revoked_by'), ev.get('reason'))
            approval_repo.append_event(token, 'revoke', {'revoked_by': ev.get('revoked_by'), 'reason': ev.get('reason')})
    print('Migration completed')
    return events


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--file', '-f', default='data/approvals/approvals.jsonl')
    p.add_argument('--apply', action='store_true', help='Apply migration into DB')
    p.add_argument('--force', action='store_true', help='Force re-import tokens even if seen')
    args = p.parse_args()
    migrate(args.file, dry_run=not args.apply, force=args.force)


if __name__ == '__main__':
    main()
