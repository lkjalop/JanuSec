"""Offline named pilot credential management; never prints credential values."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.backup.pilot_state import state_lock

ROLES = {
    'viewer': ['pilot.read', 'factors.search', 'grc.review'],
    'analyst': ['pilot.read', 'pilot.upload', 'factors.search', 'grc.review'],
    'administrator': ['*'],
}


def change(state: Path, subject: str, role: str, action: str, output: Path | None,
           days: int = 30):
    state = state.resolve(strict=True)
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}', subject):
        raise ValueError('invalid_principal_name')
    if role not in ROLES or not 1 <= days <= 90:
        raise ValueError('invalid_role_or_lifetime')
    if action not in {'add', 'rotate', 'revoke'}:
        raise ValueError('invalid_credential_action')
    if action != 'revoke':
        if output is None:
            raise ValueError('private_output_file_required')
        output = output.resolve()
        if output.is_relative_to(state) or any((p / '.git').exists() for p in output.parents):
            raise ValueError('credential_delivery_must_be_outside_state_and_git')
        if output.exists():
            raise FileExistsError('credential_output_already_exists')
    with state_lock(state):
        path = state / 'secrets.json'
        values = json.loads(path.read_text(encoding='utf-8'))
        entries = json.loads(values['API_KEYS_JSON'])
        matches = [entry for entry in entries if entry.get('subject') == subject]
        if (action == 'add' and matches) or (action != 'add' and not matches):
            raise ValueError('principal_exists' if matches else 'principal_not_found')
        entries = [entry for entry in entries if entry.get('subject') != subject]
        if action != 'revoke':
            tenant = json.loads((state / 'pilot.json').read_text(encoding='utf-8'))['tenant_id']
            entry = {'subject': subject, 'tenant_id': tenant, 'scopes': ROLES[role],
                     'key': secrets.token_urlsafe(48), 'expires_at': int(time.time()) + days * 86400}
            # Output is delivered privately before activation, never logged.
            fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                json.dump(entry, handle); handle.flush(); os.fsync(handle.fileno())
            entries.append(entry)
        if not any('*' in entry.get('scopes', []) for entry in entries):
            raise ValueError('cannot_remove_last_administrator')
        values['API_KEYS_JSON'] = json.dumps(entries)
        temp = state / ('secrets-' + secrets.token_hex(8) + '.tmp')
        try:
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                json.dump(values, handle); handle.flush(); os.fsync(handle.fileno())
            os.replace(temp, path)
        finally:
            temp.unlink(missing_ok=True)
    return {'subject': subject, 'action': action, 'role': role if action != 'revoke' else None,
            'restart_required': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['add', 'rotate', 'revoke'])
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--subject', required=True)
    parser.add_argument('--role', choices=ROLES, default='viewer')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--days', type=int, default=30)
    args = parser.parse_args()
    print(json.dumps(change(args.state, args.subject, args.role, args.action, args.output, args.days)))


if __name__ == '__main__':
    main()
