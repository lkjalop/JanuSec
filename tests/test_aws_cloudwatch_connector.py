import pytest
from src.connectors.aws.base import AWSConnectorConfig
from src.connectors.aws.cloudwatch import CloudWatchConnector

def test_cloudwatch_connector_init():
    cfg = AWSConnectorConfig(region="us-east-1")
    c = CloudWatchConnector(cfg)
    assert c.name == 'cloudwatch'
    assert c.cfg is cfg
