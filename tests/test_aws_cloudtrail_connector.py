import os
import pytest
from src.connectors.aws.base import AWSConnectorConfig
from src.connectors.aws.cloudtrail import CloudTrailConnector

def test_cloudtrail_connector_init():
    cfg = AWSConnectorConfig(region="us-east-1")
    c = CloudTrailConnector(cfg)
    assert c.name == 'cloudtrail'
    assert c.cfg is cfg

@pytest.mark.skipif(
    os.getenv("RUN_AWS_INTEGRATION", "0") not in ("1", "true", "yes"),
    reason="Set RUN_AWS_INTEGRATION=1 to run AWS integration fetch tests",
)
def test_cloudtrail_fetch_events():
    cfg = AWSConnectorConfig(region="us-east-1")
    c = CloudTrailConnector(cfg)
    list(c.fetch_events())
