import json
import boto3
from moto import mock_s3, mock_sqs
import os

from src.core import durable_dlq


@mock_s3
@mock_sqs
def test_drain_s3_archives_when_enabled(monkeypatch):
    region = 'us-east-1'
    s3 = boto3.client('s3', region_name=region)
    sqs = boto3.client('sqs', region_name=region)

    bucket = 'test-bucket-archive'
    s3.create_bucket(Bucket=bucket)
    q = sqs.create_queue(QueueName='test-queue')
    queue_url = q['QueueUrl']

    monkeypatch.setattr(durable_dlq, '_has_aws', True)
    monkeypatch.setattr(durable_dlq, 'S3_BUCKET', bucket)
    monkeypatch.setattr(durable_dlq, 'SQS_URL', queue_url)
    monkeypatch.setattr(durable_dlq, 'DLQ_ARCHIVE_ON_SUCCESS', True)
    monkeypatch.setattr(durable_dlq, 'DLQ_ARCHIVE_PREFIX', 'archive/')

    payload = {'base_url': 'https://example', 'events': [{'a': 1}]}
    durable_dlq.enqueue(payload)

    # ensure object present under dlq/
    resp = s3.list_objects_v2(Bucket=bucket, Prefix='dlq/')
    assert resp.get('KeyCount', 0) > 0

    # run drain which should archive objects under archive/
    out = durable_dlq.drain(limit=10)
    assert out and out[0].get('base_url') == 'https://example'

    # archive object present
    arch = s3.list_objects_v2(Bucket=bucket, Prefix='archive/')
    assert arch.get('KeyCount', 0) > 0
