"""Simple DLQ S3 drain script.

Usage:
  python scripts/dlq_drain_s3.py --bucket my-bucket --endpoint http://localhost:8080/api/v1/ingest --archive-prefix archive/ --dry-run

This script downloads objects under the `dlq/` prefix, posts them to the ingest endpoint,
and on success moves them to the `archive/` prefix (or deletes them if no archive specified).
It optionally records processed object keys in a sqlite db for idempotency.
"""
import argparse
import boto3
import requests
import sqlite3
import os
import sys
from urllib.parse import urljoin
import hmac
import hashlib
import base64
from src.core.idempotency import IdempotencyStore
from src.core.replay_utils import fingerprint_bytes, compute_hmac_sha256


def process_object(s3, bucket, key, endpoint, archive_prefix=None, db_path=None, dry_run=False, actor: str = None):
    store = IdempotencyStore(db_path) if db_path else None

    obj = s3.get_object(Bucket=bucket, Key=key)
    body = obj['Body'].read()

    # compute fingerprint and skip if processed
    fp = fingerprint_bytes(body)
    if store and store.is_processed(key=key):
        print('Skipping already processed (key):', key)
        store.record_replay(key, fp, actor or 'local', 'skipped')
        return True
    if store and store.is_processed(fingerprint=fp):
        print('Skipping already processed (fingerprint):', key)
        store.record_replay(key, fp, actor or 'local', 'skipped-fingerprint')
        return True

    if dry_run:
        print('DRY RUN: would post', key)
        return True

    headers = {'Content-Type': 'application/json'}
    # compute HMAC header if DLQ_DRAIN_HMAC_KEY set
    hmac_key_b64 = os.getenv('DLQ_DRAIN_HMAC_KEY_B64')
    hmac_key = None
    if hmac_key_b64:
        try:
            hmac_key = base64.b64decode(hmac_key_b64)
            sig = compute_hmac_sha256(hmac_key, body)
            headers['X-DLQ-HMAC-SHA256'] = sig
        except Exception as e:
            print('Failed computing HMAC', e)

    resp = requests.post(endpoint, data=body, headers=headers, timeout=30)
    if resp.status_code >= 200 and resp.status_code < 300:
        print('Posted', key, '->', resp.status_code)
        # archive or delete
        if archive_prefix:
            dest = archive_prefix.rstrip('/') + '/' + os.path.basename(key)
            s3.copy_object(Bucket=bucket, CopySource={'Bucket': bucket, 'Key': key}, Key=dest)
            s3.delete_object(Bucket=bucket, Key=key)
            print('Archived to', dest)
        else:
            s3.delete_object(Bucket=bucket, Key=key)
            print('Deleted', key)

        if store:
            store.mark_processed(key, fp, meta={'endpoint_status': resp.status_code})
            store.record_replay(key, fp, actor or 'local', 'success')

        return True
    else:
        print('Failed to post', key, 'status:', resp.status_code, resp.text[:200])
        if store:
            store.record_replay(key, fp, actor or 'local', 'failed', extra={'status': resp.status_code, 'body': resp.text[:200]})
        return False


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--bucket', required=True)
    p.add_argument('--prefix', default='dlq/')
    p.add_argument('--endpoint', required=True)
    p.add_argument('--archive-prefix', default=None)
    p.add_argument('--db-path', default='artifacts/idempotency.sqlite')
    p.add_argument('--dry-run', action='store_true')
    args = p.parse_args()

    s3 = boto3.client('s3')
    paginator = s3.get_paginator('list_objects_v2')

    for page in paginator.paginate(Bucket=args.bucket, Prefix=args.prefix):
        for obj in page.get('Contents', []):
            key = obj['Key']
            try:
                ok = process_object(s3, args.bucket, key, args.endpoint, args.archive_prefix, args.db_path, args.dry_run)
            except Exception as e:
                print('Error processing', key, e)

if __name__ == '__main__':
    main()
