#!/usr/bin/env python3
"""Collect memory image and upload to S3 with forensic metadata.

Usage:
  python scripts/collect_memory.py --file /tmp/memory.lime --collector avml --s3-bucket my-forensics-bucket --s3-prefix artifacts/memory/ --kms-key-id arn:aws:kms:... --object-lock-retain-days 365
"""
import argparse
import boto3
import hashlib
import json
import os
import sys
import time
from src.core.forensic_store import ForensicStore


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def upload_file(path, bucket, key, kms_key_id=None, object_lock_days=None):
    s3 = boto3.client('s3')
    extra = {}
    if kms_key_id:
        extra['ServerSideEncryption'] = 'aws:kms'
        extra['SSEKMSKeyId'] = kms_key_id
    if object_lock_days:
        # S3 object lock requires the bucket to have object lock enabled; pass retention mode via headers
        extra['Retention'] = {'Mode': 'GOVERNANCE', 'RetainUntilDate': (time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() + object_lock_days * 86400)))}

    with open(path, 'rb') as f:
        s3.put_object(Bucket=bucket, Key=key, Body=f, **({} if not extra else extra))


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--file', required=True)
    p.add_argument('--collector', required=True)
    p.add_argument('--s3-bucket', required=True)
    p.add_argument('--s3-prefix', default='artifacts/memory/')
    p.add_argument('--kms-key-id', default=None)
    p.add_argument('--object-lock-retain-days', type=int, default=None)
    args = p.parse_args()

    if not os.path.exists(args.file):
        print('file not found', args.file)
        sys.exit(2)

    checksum = sha256_file(args.file)
    base = os.path.basename(args.file)
    key = os.path.join(args.s3_prefix.rstrip('/'), base)

    meta = {
        'collector': args.collector,
        'collected_at': int(time.time()),
        'file_name': base,
        'sha256': checksum
    }

    # upload object
    upload_file(args.file, args.s3_bucket, key, kms_key_id=args.kms_key_id, object_lock_days=args.object_lock_retain_days)

    s3_url = f's3://{args.s3_bucket}/{key}'
    manifest = {'s3_url': s3_url, 'meta': meta}

    # record chain-of-custody into ForensicStore
    store = ForensicStore()
    store.insert_artifact(s3_url, args.collector, meta['collected_at'], checksum, meta)

    print(json.dumps(manifest))


if __name__ == '__main__':
    main()
