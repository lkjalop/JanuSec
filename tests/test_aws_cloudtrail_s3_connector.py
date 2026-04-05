import os
import pytest
from src.connectors.aws.base import AWSConnectorConfig
from src.connectors.aws.cloudtrail_s3 import CloudTrailS3Connector

def test_cloudtrail_s3_connector_init():
    cfg = AWSConnectorConfig(region="us-east-1")
    c = CloudTrailS3Connector(cfg, bucket="test-bucket", prefix="logs/")
    assert c.bucket == "test-bucket"
    assert c.name.startswith('cloudtrail_s3_')

@pytest.mark.skipif(
    os.getenv("RUN_AWS_INTEGRATION", "0") not in ("1", "true", "yes"),
    reason="Set RUN_AWS_INTEGRATION=1 to run AWS integration fetch tests",
)
def test_cloudtrail_s3_fetch_events():
    cfg = AWSConnectorConfig(region="us-east-1")
    c = CloudTrailS3Connector(cfg, bucket="test-bucket", prefix="logs/")
    list(c.fetch_events())
