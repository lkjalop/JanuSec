#!/usr/bin/env python3
"""Simple CLI to hit the playbook reload endpoint.

Usage:
  python scripts/playbook_reload.py --url http://localhost:8000 --key $PLAYBOOK_ADMIN_KEY
"""
import os
import argparse
import requests

parser = argparse.ArgumentParser()
parser.add_argument('--url', default=os.getenv('PLAYBOOK_RELOAD_URL', 'http://localhost:8000'))
parser.add_argument('--key', default=os.getenv('PLAYBOOK_ADMIN_KEY'))
args = parser.parse_args()

headers = {}
if args.key:
    headers['X-Admin-Key'] = args.key

r = requests.post(args.url.rstrip('/') + '/api/v1/playbook/reload', headers=headers)
print(r.status_code, r.text)
