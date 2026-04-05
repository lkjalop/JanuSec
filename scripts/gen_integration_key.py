#!/usr/bin/env python3
"""Generate a Fernet key for INTEGRATIONS_ENCRYPTION_KEY and write it to /run/secrets or .env.

Usage:
  python scripts/gen_integration_key.py --to run-secret
  python scripts/gen_integration_key.py --to env
"""
from __future__ import annotations
import argparse
import os
from cryptography.fernet import Fernet

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--to', choices=['run-secret','env'], default='run-secret')
    p.add_argument('--path', help='Custom path for run-secret directory', default='/run/secrets')
    args = p.parse_args()

    key = Fernet.generate_key().decode()
    if args.to == 'run-secret':
        d = args.path
        os.makedirs(d, exist_ok=True)
        fp = os.path.join(d, 'INTEGRATIONS_ENCRYPTION_KEY')
        with open(fp, 'w', encoding='utf-8') as fh:
            fh.write(key)
        print('Wrote Fernet key to', fp)
    else:
        # write to .env in project root
        fp = os.path.join(os.getcwd(), '.env')
        line = f'INTEGRATIONS_ENCRYPTION_KEY={key}\n'
        with open(fp, 'a', encoding='utf-8') as fh:
            fh.write(line)
        print('Appended INTEGRATIONS_ENCRYPTION_KEY to', fp)

if __name__ == '__main__':
    main()
