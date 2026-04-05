import json
import os
from tests.moto import mock_s3, mock_sqs
import boto3
import pytest

from src.core import durable_dlq


@mock_s3
@mock_sqs
def test_enqueue_with_s3_and_sqs(monkeypatch):
    # Setup moto-backed S3 and SQS
    s3 = boto3.client('s3', region_name='us-east-1')
    sqs = boto3.client('sqs', region_name='us-east-1')

    bucket = 'my-dlq-bucket'
    s3.create_bucket(Bucket=bucket)
    q = sqs.create_queue(QueueName='my-dlq-queue')
    qurl = q['QueueUrl']

    # Configure env so durable_dlq uses these
    monkeypatch.setenv('DLQ_S3_BUCKET', bucket)
    monkeypatch.setenv('DLQ_SQS_URL', qurl)
    durable_dlq.S3_BUCKET = bucket
    durable_dlq.SQS_URL = qurl
    durable_dlq._has_aws = True

    payload = {'base_url': 'https://example', 'events': [{'a': 1}]}

    durable_dlq.enqueue(payload)

    # Inspect S3 objects in bucket to ensure object written
    objs = s3.list_objects_v2(Bucket=bucket)
    assert objs.get('KeyCount', 0) >= 1


@mock_s3
@mock_sqs
def test_drain_sqs_fetches_from_s3(monkeypatch):
    s3 = boto3.client('s3', region_name='us-east-1')
    sqs = boto3.client('sqs', region_name='us-east-1')

    bucket = 'my-dlq-bucket'
    s3.create_bucket(Bucket=bucket)
    q = sqs.create_queue(QueueName='my-dlq-queue')
    qurl = q['QueueUrl']

    monkeypatch.setenv('DLQ_S3_BUCKET', bucket)
    monkeypatch.setenv('DLQ_SQS_URL', qurl)
    durable_dlq.S3_BUCKET = bucket
    durable_dlq.SQS_URL = qurl
    durable_dlq._has_aws = True

    # Put a payload into S3 and send pointer to SQS
    actual = {'base_url': 'https://example', 'events': [{'a': 2}]}
    key = 'dlq/123-abc.json'
    s3.put_object(Bucket=bucket, Key=key, Body=json.dumps(actual).encode('utf-8'))
    sqs.send_message(QueueUrl=qurl, MessageBody=json.dumps({'s3_key': key}))

    out = durable_dlq.drain_sqs(limit=10)
    assert isinstance(out, list)
    assert out[0].get('base_url') == 'https://example'


def test_fallback_to_file(tmp_path, monkeypatch):
    # Simulate no AWS available
    monkeypatch.setenv('DLQ_SQS_URL', '')
    monkeypatch.setenv('DLQ_S3_BUCKET', '')
    monkeypatch.setattr(durable_dlq, '_has_aws', False)

    # Use temporary file path for artifacts
    art = tmp_path / 'artifacts'
    art.mkdir()
    monkeypatch.setattr(durable_dlq, '_file_dlq', str(art / 'writeback_dlq.jsonl'))

    payload = {'base_url': 'https://example', 'events': [{'a': 3}]}
    durable_dlq._file_enqueue(payload)

    items = durable_dlq.file_drain(limit=10)
    assert items[0].get('base_url') == 'https://example'
