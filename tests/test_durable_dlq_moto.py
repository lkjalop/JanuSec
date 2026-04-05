import os
import json
import boto3
import pytest
from tests.moto import mock_s3, mock_sqs, mock_kms

from src.core import durable_dlq


@mock_s3
@mock_sqs
def test_durable_dlq_with_moto(monkeypatch):
    # Create moto-backed S3 and SQS
    s3 = boto3.client('s3', region_name='us-east-1')
    sqs = boto3.client('sqs', region_name='us-east-1')

    bucket = 'test-dlq-bucket'
    s3.create_bucket(Bucket=bucket)
    q = sqs.create_queue(QueueName='test-dlq-queue')
    qurl = q['QueueUrl']

    # configure durable_dlq to use moto endpoints via real boto3 client but default URLs
    monkeypatch.setenv('DLQ_S3_BUCKET', bucket)
    monkeypatch.setenv('DLQ_SQS_URL', qurl)
    durable_dlq.S3_BUCKET = bucket
    durable_dlq.SQS_URL = qurl

    # Use real boto3 inside durable_dlq by ensuring _has_aws True
    durable_dlq._has_aws = True

    # enqueue an item
    item = {'base_url': 'https://example', 'api_key': 'k', 'tenant_id': 't', 'events': [{'a':1}]}
    durable_dlq.enqueue(item)

    # receive via durable_dlq.drain()
    out = durable_dlq.drain(limit=10)
    assert out and out[0].get('base_url') == 'https://example'
