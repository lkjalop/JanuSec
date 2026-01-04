import json
import boto3
import pytest
from moto import mock_s3, mock_sqs

from src.core import durable_dlq


@mock_s3
@mock_sqs
def test_enqueue_and_drain_s3_sqs(monkeypatch):
    # Use moto to create real S3 bucket and SQS queue
    region = 'us-east-1'
    s3 = boto3.client('s3', region_name=region)
    sqs = boto3.client('sqs', region_name=region)

    bucket = 'test-bucket'
    s3.create_bucket(Bucket=bucket)
    q = sqs.create_queue(QueueName='test-queue')
    queue_url = q['QueueUrl']

    # Patch durable_dlq module to point to moto resources
    monkeypatch.setattr(durable_dlq, '_has_aws', True)
    monkeypatch.setattr(durable_dlq, 'S3_BUCKET', bucket)
    monkeypatch.setattr(durable_dlq, 'SQS_URL', queue_url)

    item = {'base_url': 'https://example', 'api_key': 'k', 'tenant_id': 't', 'events': [{'a':1}]}

    # Enqueue should write object to S3 and send a pointer to SQS
    durable_dlq.enqueue(item)

    # Confirm S3 object exists under dlq/ prefix
    resp = s3.list_objects_v2(Bucket=bucket, Prefix='dlq/')
    assert resp.get('KeyCount', 0) > 0

    # Run drain which should pull pointers from SQS and fetch from S3
    out = durable_dlq.drain(limit=10)
    assert isinstance(out, list)
    assert out and out[0].get('base_url') == 'https://example'
