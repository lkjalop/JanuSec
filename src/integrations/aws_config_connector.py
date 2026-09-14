"""AWS Config / CloudTrail connector scaffold.

Provides:
- AssumeRole helper for multi-account
- S3-based CloudTrail JSON processor (reads objects from S3 and yields normalized events)

This is a lightweight scaffold that uses boto3 when available; in test/demo mode it falls
back to local file reading based on a configured directory.
"""
from __future__ import annotations
import json
import time
import logging
from typing import Iterable, Dict, Any, Optional

logger = logging.getLogger(__name__)

try:
    import boto3
    from botocore.exceptions import ClientError
except Exception:
    boto3 = None
    logger.warning(
        'AWS connector: boto3 not installed — AWS live connector is non-functional. '
        'Install with: pip install boto3 botocore'
    )


def assume_role(account_id: str, role_name: str, session_name: str = 'janusec-assume') -> Optional[Dict[str, Any]]:
    if boto3 is None:
        logger.warning('assume_role: boto3 unavailable — install boto3 to enable AWS live connector')
        return None
    sts = boto3.client('sts')
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    try:
        res = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name, DurationSeconds=3600)
        return res.get('Credentials')
    except ClientError as e:
        logger.warning('AssumeRole failed: %s', e)
        return None


def iter_cloudtrail_s3(bucket: str, prefix: Optional[str] = None, aws_creds: Optional[Dict[str, Any]] = None) -> Iterable[Dict[str, Any]]:
    """Yield normalized CloudTrail-like events from S3 objects in `bucket/prefix`.
    If boto3 isn't available or credentials are None, this falls back to reading local files under prefix.
    """
    if boto3 is None or aws_creds is None:
        # Local file fallback: treat prefix as a directory
        import os
        basedir = prefix or 'data/cloudtrail'
        if not os.path.isdir(basedir):
            return
        for fname in sorted(os.listdir(basedir)):
            if not fname.endswith('.json'):
                continue
            p = os.path.join(basedir, fname)
            try:
                with open(p, 'r', encoding='utf-8') as fh:
                    j = json.load(fh)
                for rec in (j.get('Records') or []):
                    yield normalize_cloudtrail_record(rec)
            except Exception:
                continue
        return

    s3 = boto3.client('s3', aws_access_key_id=aws_creds.get('AccessKeyId'), aws_secret_access_key=aws_creds.get('SecretAccessKey'), aws_session_token=aws_creds.get('SessionToken'))
    paginator = s3.get_paginator('list_objects_v2')
    kwargs = {'Bucket': bucket}
    if prefix:
        kwargs['Prefix'] = prefix
    try:
        for page in paginator.paginate(**kwargs):
            for obj in page.get('Contents', []):
                key = obj.get('Key')
                try:
                    res = s3.get_object(Bucket=bucket, Key=key)
                    body = res['Body'].read()
                    j = json.loads(body)
                    for rec in (j.get('Records') or []):
                        yield normalize_cloudtrail_record(rec)
                except Exception:
                    continue
    except Exception:
        return


def normalize_cloudtrail_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    user = (rec.get('userIdentity') or {}).get('userName') or (rec.get('userIdentity') or {}).get('arn')
    evt = {
        'source': 'cloudtrail',
        'ts': rec.get('eventTime'),
        'user': user,
        'host': rec.get('recipientAccountId'),
        'event_name': rec.get('eventName'),
        'service': rec.get('eventSource'),
        'request_ip': rec.get('sourceIPAddress'),
        'raw': rec,
    }
    return {k: v for k, v in evt.items() if v is not None}


if __name__ == '__main__':
    print('AWS Config connector scaffold - not for production use as-is')
