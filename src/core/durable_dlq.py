"""Durable DLQ using SQS for messages and optional S3 backup for bodies.

If AWS credentials/env are not set, falls back to the file-based DLQ.
Exposes a Prometheus gauge `writeback_dlq_depth` when `prometheus_client` is available.
"""
from __future__ import annotations

import json
import os
import logging
import hashlib
from typing import Any, Dict, Optional, List

logger = logging.getLogger(__name__)

SQS_URL = os.getenv('DLQ_SQS_URL')
S3_BUCKET = os.getenv('DLQ_S3_BUCKET')
DLQ_ARCHIVE_ON_SUCCESS = os.getenv('DLQ_ARCHIVE_ON_SUCCESS', '0') in ('1', 'true', 'True')
DLQ_ARCHIVE_PREFIX = os.getenv('DLQ_ARCHIVE_PREFIX', 'archive/')

_has_aws = False
try:
    import boto3
    _has_aws = True
except Exception:
    boto3 = None

try:
    from prometheus_client import Gauge
    DLQ_GAUGE = Gauge('writeback_dlq_depth', 'Approximate number of messages in writeback DLQ')
    from prometheus_client import Counter
    DLQ_S3_BACKUP_SUCCESS = Counter('writeback_dlq_s3_backup_success_total', 'Total S3 backup successes')
    DLQ_S3_BACKUP_FAILURE = Counter('writeback_dlq_s3_backup_failure_total', 'Total S3 backup failures')
    DLQ_SQS_SEND_SUCCESS = Counter('writeback_dlq_sqs_send_success_total', 'Total SQS send successes')
    DLQ_SQS_SEND_FAILURE = Counter('writeback_dlq_sqs_send_failure_total', 'Total SQS send failures')
except Exception:
    DLQ_GAUGE = None
    DLQ_S3_BACKUP_SUCCESS = None
    DLQ_S3_BACKUP_FAILURE = None
    DLQ_SQS_SEND_SUCCESS = None
    DLQ_SQS_SEND_FAILURE = None
    try:
        DLQ_S3_ARCHIVE = Counter('writeback_dlq_s3_archive_total', 'Total S3 archive (on successful drain)')
        DLQ_S3_DELETE = Counter('writeback_dlq_s3_delete_total', 'Total S3 deletes')
    except Exception:
        DLQ_S3_ARCHIVE = None
        DLQ_S3_DELETE = None

_file_dlq = os.path.join('artifacts', 'writeback_dlq.jsonl')
os.makedirs(os.path.dirname(_file_dlq) or '.', exist_ok=True)


def _file_enqueue(payload: Dict[str, Any]) -> None:
    try:
        with open(_file_dlq, 'a', encoding='utf-8') as f:
            f.write(json.dumps({'ts': int(__import__('time').time()), 'payload': payload}) + '\n')
    except Exception:
        logger.exception('file dlq write failed')


def enqueue(payload: Dict[str, Any]) -> None:
    """Enqueue payload to durable DLQ: prefer SQS, backup to S3 if configured, else fallback to file."""
    # Prefer S3-backed retention when available: upload body to S3 and send lightweight SQS pointer.
    if _has_aws and S3_BUCKET:
        try:
            s3 = boto3.client('s3')
            body = json.dumps(payload, default=str)
            key = f"dlq/{int(__import__('time').time())}-{hashlib.sha256(body.encode('utf-8')).hexdigest()}.json"
            put_kwargs = {'Bucket': S3_BUCKET, 'Key': key, 'Body': body.encode('utf-8')}
            # Optional server-side encryption via KMS
            kms_key = os.getenv('DLQ_S3_SSE_KMS_KEY')
            if kms_key:
                put_kwargs['ServerSideEncryption'] = 'aws:kms'
                put_kwargs['SSEKMSKeyId'] = kms_key
            s3.put_object(**put_kwargs)
            if DLQ_S3_BACKUP_SUCCESS:
                try:
                    DLQ_S3_BACKUP_SUCCESS.inc()
                except Exception:
                    pass
            # Build SQS pointer message when SQS available
            if SQS_URL:
                try:
                    client = boto3.client('sqs')
                    message = {'s3_key': key}
                    client.send_message(QueueUrl=SQS_URL, MessageBody=json.dumps(message))
                    if DLQ_SQS_SEND_SUCCESS:
                        try:
                            DLQ_SQS_SEND_SUCCESS.inc()
                        except Exception:
                            pass
                    # update gauge best-effort
                    try:
                        if DLQ_GAUGE:
                            attrs = client.get_queue_attributes(QueueUrl=SQS_URL, AttributeNames=['ApproximateNumberOfMessages'])
                            n = int(attrs.get('Attributes', {}).get('ApproximateNumberOfMessages', 0))
                            DLQ_GAUGE.set(n)
                    except Exception:
                        pass
                    return
                except Exception:
                    logger.exception('SQS pointer send failed; retaining S3 object (will retry send later)')
                    if DLQ_SQS_SEND_FAILURE:
                        try:
                            DLQ_SQS_SEND_FAILURE.inc()
                        except Exception:
                            pass
                    # do not remove S3 object; fallback to file enqueue of metadata
            else:
                # No SQS configured: S3-only retention — success
                return
        except Exception:
            logger.exception('S3 backup failed')
            if DLQ_S3_BACKUP_FAILURE:
                try:
                    DLQ_S3_BACKUP_FAILURE.inc()
                except Exception:
                    pass
            # fallthrough to SQS or file
    if _has_aws and SQS_URL:
        try:
            client = boto3.client('sqs')
            body = json.dumps(payload, default=str)
            message = {'body': body}
            client.send_message(QueueUrl=SQS_URL, MessageBody=json.dumps(message))
            if DLQ_SQS_SEND_SUCCESS:
                try:
                    DLQ_SQS_SEND_SUCCESS.inc()
                except Exception:
                    pass
            # update gauge (best-effort: approximate via GetQueueAttributes may be costly)
            try:
                if DLQ_GAUGE:
                    attrs = client.get_queue_attributes(QueueUrl=SQS_URL, AttributeNames=['ApproximateNumberOfMessages'])
                    n = int(attrs.get('Attributes', {}).get('ApproximateNumberOfMessages', 0))
                    DLQ_GAUGE.set(n)
            except Exception:
                pass
            return
        except Exception:
            logger.exception('SQS enqueue failed, falling back to file DLQ')
            if DLQ_SQS_SEND_FAILURE:
                try:
                    DLQ_SQS_SEND_FAILURE.inc()
                except Exception:
                    pass
    # fallback
    _file_enqueue(payload)


def drain_sqs(limit: int = 100) -> List[Dict[str, Any]]:
    """Drain up to `limit` messages from SQS and return parsed payloads. Removes messages on success.

    If SQS not configured, return empty list.
    """
    out = []
    if not (_has_aws and SQS_URL):
        return out
    try:
        client = boto3.client('sqs')
        resp = client.receive_message(QueueUrl=SQS_URL, MaxNumberOfMessages=min(10, limit), WaitTimeSeconds=1)
        msgs = resp.get('Messages') or []
        for m in msgs:
            try:
                raw = json.loads(m.get('Body') or '{}')
                # If message references S3, fetch the object
                if isinstance(raw, dict) and raw.get('s3_key') and S3_BUCKET:
                    try:
                        s3 = boto3.client('s3')
                        obj = s3.get_object(Bucket=S3_BUCKET, Key=raw['s3_key'])
                        body = obj['Body'].read().decode('utf-8')
                        parsed = json.loads(body)
                        out.append(parsed)
                    except Exception:
                        logger.exception('Failed to fetch DLQ body from S3; using inline body if present')
                        # fallback to any inline body
                        body = json.loads(raw.get('body') or '{}')
                        out.append(body)
                else:
                    body = json.loads(raw.get('body') if isinstance(raw, dict) else (m.get('Body') or '{}'))
                    out.append(body)
                client.delete_message(QueueUrl=SQS_URL, ReceiptHandle=m['ReceiptHandle'])
            except Exception:
                logger.exception('Failed processing message from DLQ')
    except Exception:
        logger.exception('Failed to drain SQS')
    return out


def drain_s3(limit: int = 100) -> List[Dict[str, Any]]:
    """When S3-only retention is used (no SQS), list recent objects under dlq/ prefix and return parsed payloads.

    This is a best-effort helper for operator drains when SQS pointers are not used.
    """
    out = []
    if not (_has_aws and S3_BUCKET):
        return out
    try:
        s3 = boto3.client('s3')
        resp = s3.list_objects_v2(Bucket=S3_BUCKET, Prefix='dlq/', MaxKeys=min(1000, limit))
        objs = resp.get('Contents') or []
        for o in objs[:limit]:
            try:
                key = o.get('Key')
                obj = s3.get_object(Bucket=S3_BUCKET, Key=key)
                body = obj['Body'].read().decode('utf-8')
                parsed = json.loads(body)
                out.append(parsed)
                # Optionally archive (move) object after retrieval to avoid reprocessing
                try:
                    if DLQ_ARCHIVE_ON_SUCCESS:
                        dest_key = DLQ_ARCHIVE_PREFIX.rstrip('/') + '/' + key.split('/', 1)[-1]
                        # copy then delete
                        s3.copy_object(Bucket=S3_BUCKET, CopySource={'Bucket': S3_BUCKET, 'Key': key}, Key=dest_key)
                        s3.delete_object(Bucket=S3_BUCKET, Key=key)
                        if DLQ_S3_ARCHIVE:
                            try:
                                DLQ_S3_ARCHIVE.inc()
                            except Exception:
                                pass
                    else:
                        s3.delete_object(Bucket=S3_BUCKET, Key=key)
                        if DLQ_S3_DELETE:
                            try:
                                DLQ_S3_DELETE.inc()
                            except Exception:
                                pass
                except Exception:
                    pass
            except Exception:
                logger.exception('Failed to fetch DLQ object from S3')
    except Exception:
        logger.exception('Failed to list DLQ S3 objects')
    return out


def file_drain(limit: int = 100) -> List[Dict[str, Any]]:
    out = []
    try:
        with open(_file_dlq, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        return out
    remaining = lines[limit:]
    for line in lines[:limit]:
        try:
            obj = json.loads(line)
            out.append(obj.get('payload'))
        except Exception:
            pass
    try:
        with open(_file_dlq, 'w', encoding='utf-8') as f:
            for ln in remaining:
                f.write(ln)
    except Exception:
        logger.exception('Failed to rewrite file DLQ')
    return out


def drain(limit: int = 100) -> List[Dict[str, Any]]:
    # Prefer SQS pointer drain when configured
    if _has_aws and SQS_URL:
        return drain_sqs(limit)
    # If S3-only retention is configured, attempt S3 drain
    if _has_aws and S3_BUCKET:
        return drain_s3(limit)
    return file_drain(limit)


__all__ = ['enqueue', 'drain']
